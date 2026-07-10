#include "transport/local_transport_nimble_peripheral.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "host/ble_att.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "sdkconfig.h"
#include "transport/local_transport_profile.h"

namespace signing {
namespace {

constexpr const char* kTag = "LocalTransportBle";
constexpr size_t kDeviceNameBytes = 32;
constexpr int64_t kAdvertisingRetryDelayUs = 1000 * 1000;
constexpr uint16_t kPreferredAttMtu =
    static_cast<uint16_t>(CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU);
constexpr size_t kFingerprintBytes = 8;
constexpr size_t kServiceDataBytes = 16 + kFingerprintBytes;

// a6e31d10-51a1-4f7a-9b0a-0a1c00000001
// NimBLE's BLE_UUID128_INIT takes bytes least-significant first.
const ble_uuid128_t kServiceUuid = BLE_UUID128_INIT(
    0x01, 0x00, 0x00, 0x00, 0x1c, 0x0a, 0x0a, 0x9b,
    0x7a, 0x4f, 0xa1, 0x51, 0x10, 0x1d, 0xe3, 0xa6);
const ble_uuid128_t kPairingCtrlUuid = BLE_UUID128_INIT(
    0x02, 0x00, 0x00, 0x00, 0x1c, 0x0a, 0x0a, 0x9b,
    0x7a, 0x4f, 0xa1, 0x51, 0x10, 0x1d, 0xe3, 0xa6);
const ble_uuid128_t kPairingDataUuid = BLE_UUID128_INIT(
    0x03, 0x00, 0x00, 0x00, 0x1c, 0x0a, 0x0a, 0x9b,
    0x7a, 0x4f, 0xa1, 0x51, 0x10, 0x1d, 0xe3, 0xa6);

portMUX_TYPE g_state_lock = portMUX_INITIALIZER_UNLOCKED;
bool g_host_started = false;
bool g_host_failed = false;
bool g_host_synced = false;
bool g_advertising_requested = false;
bool g_advertising_active = false;
bool g_advertising_restart_pending = false;
int64_t g_next_advertising_retry_us = 0;
uint8_t g_own_addr_type = 0;
uint8_t g_advertised_fingerprint[kFingerprintBytes] = {};
uint16_t g_conn_handle = BLE_HS_CONN_HANDLE_NONE;
uint16_t g_pairing_ctrl_val_handle = 0;
uint16_t g_pairing_data_val_handle = 0;
bool g_pairing_ctrl_indicate_enabled = false;
bool g_pairing_data_indicate_enabled = false;
StaticSemaphore_t g_indication_completion_storage;
SemaphoreHandle_t g_indication_completion = nullptr;
bool g_indication_pending = false;
uint16_t g_indication_conn_handle = BLE_HS_CONN_HANDLE_NONE;
uint16_t g_indication_attr_handle = 0;
int g_indication_completion_status = BLE_HS_ETIMEOUT;
bool g_inbound_pending = false;
char g_device_name[kDeviceNameBytes] = {};
LocalTransportBleInboundFrame* g_inbound_frame = nullptr;

ble_gatt_chr_def g_chr_defs[3];
ble_gatt_svc_def g_svc_defs[2];

void clear_inbound_frame_locked()
{
    g_inbound_pending = false;
    if (g_inbound_frame != nullptr) {
        memset(g_inbound_frame, 0, sizeof(*g_inbound_frame));
    }
}

void copy_advertised_fingerprint(uint8_t output[kFingerprintBytes])
{
    portENTER_CRITICAL(&g_state_lock);
    memcpy(output, g_advertised_fingerprint, kFingerprintBytes);
    portEXIT_CRITICAL(&g_state_lock);
}

bool advertising_requested()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool requested = g_advertising_requested;
    portEXIT_CRITICAL(&g_state_lock);
    return requested;
}

void set_advertising_active(bool active)
{
    portENTER_CRITICAL(&g_state_lock);
    g_advertising_active = active;
    portEXIT_CRITICAL(&g_state_lock);
}

void request_advertising_restart_if_needed(int64_t delay_us = 0)
{
    portENTER_CRITICAL(&g_state_lock);
    if (g_advertising_requested) {
        g_advertising_restart_pending = true;
        g_next_advertising_retry_us = esp_timer_get_time() + delay_us;
    }
    portEXIT_CRITICAL(&g_state_lock);
}

void set_host_synced(uint8_t own_addr_type)
{
    portENTER_CRITICAL(&g_state_lock);
    g_host_synced = true;
    g_own_addr_type = own_addr_type;
    portEXIT_CRITICAL(&g_state_lock);
}

void clear_host_synced()
{
    portENTER_CRITICAL(&g_state_lock);
    g_host_synced = false;
    g_own_addr_type = 0;
    portEXIT_CRITICAL(&g_state_lock);
}

bool host_synced(uint8_t* own_addr_type)
{
    portENTER_CRITICAL(&g_state_lock);
    const bool synced = g_host_synced;
    if (own_addr_type != nullptr) {
        *own_addr_type = g_own_addr_type;
    }
    portEXIT_CRITICAL(&g_state_lock);
    return synced;
}

void set_connection_handle(uint16_t conn_handle)
{
    portENTER_CRITICAL(&g_state_lock);
    if (g_conn_handle != conn_handle) {
        g_pairing_ctrl_indicate_enabled = false;
        g_pairing_data_indicate_enabled = false;
        clear_inbound_frame_locked();
    }
    g_conn_handle = conn_handle;
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        g_pairing_ctrl_indicate_enabled = false;
        g_pairing_data_indicate_enabled = false;
        clear_inbound_frame_locked();
    }
    portEXIT_CRITICAL(&g_state_lock);
}

uint16_t connection_handle()
{
    portENTER_CRITICAL(&g_state_lock);
    const uint16_t handle = g_conn_handle;
    portEXIT_CRITICAL(&g_state_lock);
    return handle;
}

bool ensure_indication_completion()
{
    if (g_indication_completion != nullptr) {
        return true;
    }
    g_indication_completion = xSemaphoreCreateBinaryStatic(&g_indication_completion_storage);
    return g_indication_completion != nullptr;
}

bool begin_indication(uint16_t conn_handle, uint16_t attr_handle)
{
    if (!ensure_indication_completion()) {
        return false;
    }
    while (xSemaphoreTake(g_indication_completion, 0) == pdTRUE) {
    }

    portENTER_CRITICAL(&g_state_lock);
    if (g_indication_pending) {
        portEXIT_CRITICAL(&g_state_lock);
        return false;
    }
    g_indication_pending = true;
    g_indication_conn_handle = conn_handle;
    g_indication_attr_handle = attr_handle;
    g_indication_completion_status = BLE_HS_ETIMEOUT;
    portEXIT_CRITICAL(&g_state_lock);
    return true;
}

void complete_indication(
    uint16_t conn_handle,
    uint16_t attr_handle,
    int status)
{
    if (status == 0) {
        return;
    }
    bool signal = false;
    portENTER_CRITICAL(&g_state_lock);
    if (g_indication_pending &&
        g_indication_conn_handle == conn_handle &&
        g_indication_attr_handle == attr_handle) {
        g_indication_pending = false;
        g_indication_completion_status = status;
        signal = true;
    }
    portEXIT_CRITICAL(&g_state_lock);
    if (signal && g_indication_completion != nullptr) {
        xSemaphoreGive(g_indication_completion);
    }
}

void fail_indication_for_connection(uint16_t conn_handle, int status)
{
    bool signal = false;
    portENTER_CRITICAL(&g_state_lock);
    if (g_indication_pending && g_indication_conn_handle == conn_handle) {
        g_indication_pending = false;
        g_indication_completion_status = status;
        signal = true;
    }
    portEXIT_CRITICAL(&g_state_lock);
    if (signal && g_indication_completion != nullptr) {
        xSemaphoreGive(g_indication_completion);
    }
}

void abandon_indication(uint16_t conn_handle, uint16_t attr_handle)
{
    portENTER_CRITICAL(&g_state_lock);
    if (g_indication_pending &&
        g_indication_conn_handle == conn_handle &&
        g_indication_attr_handle == attr_handle) {
        g_indication_pending = false;
        g_indication_completion_status = BLE_HS_ETIMEOUT;
    }
    portEXIT_CRITICAL(&g_state_lock);
}

int indication_completion_status()
{
    portENTER_CRITICAL(&g_state_lock);
    const int status = g_indication_completion_status;
    portEXIT_CRITICAL(&g_state_lock);
    return status;
}

bool set_advertising_fields()
{
    uint8_t service_data[kServiceDataBytes] = {};
    memcpy(service_data, kServiceUuid.value, 16);
    copy_advertised_fingerprint(service_data + 16);

    ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = const_cast<ble_uuid128_t*>(&kServiceUuid);
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(kTag, "adv_set_fields failed rc=%d", rc);
        return false;
    }

    ble_hs_adv_fields response;
    memset(&response, 0, sizeof(response));
    response.svc_data_uuid128 = service_data;
    response.svc_data_uuid128_len = sizeof(service_data);
    rc = ble_gap_adv_rsp_set_fields(&response);
    if (rc != 0) {
        ESP_LOGW(kTag, "adv_rsp_set_fields failed rc=%d", rc);
        return false;
    }
    return true;
}

uint16_t current_att_mtu_for_connection(uint16_t conn_handle)
{
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        return 23;
    }
    const uint16_t mtu = ble_att_mtu(conn_handle);
    return mtu == 0 ? 23 : mtu;
}

bool channel_for_attr_handle(uint16_t attr_handle, LocalTransportBleChannel* channel)
{
    if (channel == nullptr) {
        return false;
    }
    if (attr_handle == g_pairing_ctrl_val_handle) {
        *channel = LocalTransportBleChannel::control;
        return true;
    }
    if (attr_handle == g_pairing_data_val_handle) {
        *channel = LocalTransportBleChannel::data;
        return true;
    }
    return false;
}

uint16_t value_handle_for_channel(LocalTransportBleChannel channel)
{
    switch (channel) {
        case LocalTransportBleChannel::control:
            return g_pairing_ctrl_val_handle;
        case LocalTransportBleChannel::data:
            return g_pairing_data_val_handle;
    }
    return 0;
}

bool indication_enabled_for_channel(LocalTransportBleChannel channel)
{
    portENTER_CRITICAL(&g_state_lock);
    bool enabled = false;
    switch (channel) {
        case LocalTransportBleChannel::control:
            enabled = g_pairing_ctrl_indicate_enabled;
            break;
        case LocalTransportBleChannel::data:
            enabled = g_pairing_data_indicate_enabled;
            break;
    }
    portEXIT_CRITICAL(&g_state_lock);
    return enabled;
}

int enqueue_inbound_frame(
    LocalTransportBleChannel channel,
    uint16_t conn_handle,
    const os_mbuf* om)
{
    if (om == nullptr) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    const int length = OS_MBUF_PKTLEN(om);
    if (length <= 0 || static_cast<size_t>(length) > kLocalTransportBleMaxPayloadBytes) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    portENTER_CRITICAL(&g_state_lock);
    const bool already_pending = g_inbound_pending;
    portEXIT_CRITICAL(&g_state_lock);
    if (already_pending) {
        return BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    LocalTransportBleInboundFrame next = {};
    next.channel = channel;
    next.conn_handle = conn_handle;
    next.att_mtu = current_att_mtu_for_connection(conn_handle);
    next.length = static_cast<size_t>(length);
    if (os_mbuf_copydata(om, 0, length, next.payload) != 0) {
        memset(&next, 0, sizeof(next));
        return BLE_ATT_ERR_UNLIKELY;
    }

    portENTER_CRITICAL(&g_state_lock);
    if (g_inbound_pending) {
        portEXIT_CRITICAL(&g_state_lock);
        memset(&next, 0, sizeof(next));
        return BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    if (g_inbound_frame == nullptr) {
        portEXIT_CRITICAL(&g_state_lock);
        memset(&next, 0, sizeof(next));
        return BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    *g_inbound_frame = next;
    g_inbound_pending = true;
    portEXIT_CRITICAL(&g_state_lock);
    return 0;
}

bool start_advertising_if_ready()
{
    portENTER_CRITICAL(&g_state_lock);
    g_advertising_restart_pending = false;
    g_next_advertising_retry_us = 0;
    portEXIT_CRITICAL(&g_state_lock);

    uint8_t own_addr_type = 0;
    if (!host_synced(&own_addr_type)) {
        return true;
    }
    if (!advertising_requested()) {
        return true;
    }
    const uint16_t connected_handle = connection_handle();
    if (connected_handle != BLE_HS_CONN_HANDLE_NONE) {
        const int rc = ble_gap_terminate(connected_handle, BLE_ERR_REM_USER_CONN_TERM);
        if (rc != 0) {
            ESP_LOGW(kTag,
                     "pairing advertising requested while connected; terminate failed rc=%d",
                     rc);
        } else {
            ESP_LOGW(kTag,
                     "pairing advertising requested while connected; terminating conn=%u",
                     (unsigned)connected_handle);
        }
        request_advertising_restart_if_needed(kAdvertisingRetryDelayUs);
        return true;
    }
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
    }
    if (!set_advertising_fields()) {
        request_advertising_restart_if_needed(kAdvertisingRetryDelayUs);
        return true;
    }

    ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    const int rc = ble_gap_adv_start(
        own_addr_type,
        nullptr,
        BLE_HS_FOREVER,
        &params,
        [](ble_gap_event* event, void*) -> int {
            switch (event->type) {
                case BLE_GAP_EVENT_CONNECT:
                    if (event->connect.status == 0) {
                        set_connection_handle(event->connect.conn_handle);
                        set_advertising_active(false);
                        ESP_LOGI(kTag, "connected conn=%u",
                                 (unsigned)event->connect.conn_handle);
                    } else {
                        set_connection_handle(BLE_HS_CONN_HANDLE_NONE);
                        set_advertising_active(false);
                        ESP_LOGW(kTag, "connect failed status=%d",
                                 event->connect.status);
                        request_advertising_restart_if_needed();
                    }
                    return 0;
                case BLE_GAP_EVENT_DISCONNECT:
                    ESP_LOGW(kTag, "disconnected conn=%u reason=%d",
                             (unsigned)event->disconnect.conn.conn_handle,
                             event->disconnect.reason);
                    fail_indication_for_connection(
                        event->disconnect.conn.conn_handle,
                        BLE_HS_ENOTCONN);
                    set_connection_handle(BLE_HS_CONN_HANDLE_NONE);
                    set_advertising_active(false);
                    request_advertising_restart_if_needed();
                    return 0;
                case BLE_GAP_EVENT_ADV_COMPLETE:
                    set_advertising_active(false);
                    request_advertising_restart_if_needed();
                    return 0;
                case BLE_GAP_EVENT_MTU:
                    ESP_LOGI(kTag, "mtu conn=%u value=%u",
                             (unsigned)event->mtu.conn_handle,
                             (unsigned)event->mtu.value);
                    return 0;
                case BLE_GAP_EVENT_SUBSCRIBE:
                    portENTER_CRITICAL(&g_state_lock);
                    if (event->subscribe.attr_handle == g_pairing_ctrl_val_handle) {
                        g_pairing_ctrl_indicate_enabled = event->subscribe.cur_indicate;
                    } else if (event->subscribe.attr_handle == g_pairing_data_val_handle) {
                        g_pairing_data_indicate_enabled = event->subscribe.cur_indicate;
                    }
                    portEXIT_CRITICAL(&g_state_lock);
                    ESP_LOGI(kTag, "subscribe attr=%u notify=%d indicate=%d",
                             (unsigned)event->subscribe.attr_handle,
                             event->subscribe.cur_notify,
                             event->subscribe.cur_indicate);
                    return 0;
                case BLE_GAP_EVENT_NOTIFY_TX:
                    ESP_LOGI(kTag, "indication tx attr=%u status=%d",
                             (unsigned)event->notify_tx.attr_handle,
                             event->notify_tx.status);
                    if (event->notify_tx.indication) {
                        complete_indication(
                            event->notify_tx.conn_handle,
                            event->notify_tx.attr_handle,
                            event->notify_tx.status);
                    }
                    return 0;
                default:
                    return 0;
            }
        },
        nullptr);
    if (rc != 0) {
        ESP_LOGW(kTag, "adv_start failed rc=%d", rc);
        set_advertising_active(false);
        request_advertising_restart_if_needed(kAdvertisingRetryDelayUs);
        return true;
    }
    set_advertising_active(true);
    return true;
}

int gatt_access_cb(
    uint16_t conn_handle,
    uint16_t attr_handle,
    ble_gatt_access_ctxt* ctxt,
    void*)
{
    if (ctxt == nullptr) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }
    LocalTransportBleChannel channel = LocalTransportBleChannel::control;
    if (!channel_for_attr_handle(attr_handle, &channel)) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    return enqueue_inbound_frame(channel, conn_handle, ctxt->om);
}

void on_reset(int reason)
{
    clear_host_synced();
    set_advertising_active(false);
    set_connection_handle(BLE_HS_CONN_HANDLE_NONE);
    ESP_LOGW(kTag, "host reset reason=%d", reason);
}

void on_sync()
{
    int rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGW(kTag, "ensure_addr failed rc=%d", rc);
        return;
    }

    uint8_t own_addr_type = 0;
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGW(kTag, "infer_auto failed rc=%d", rc);
        return;
    }
    set_host_synced(own_addr_type);
    start_advertising_if_ready();
}

void host_task(void*)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

bool configure_gatt()
{
    memset(g_chr_defs, 0, sizeof(g_chr_defs));
    g_chr_defs[0].uuid = &kPairingCtrlUuid.u;
    g_chr_defs[0].access_cb = gatt_access_cb;
    g_chr_defs[0].flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_INDICATE;
    g_chr_defs[0].val_handle = &g_pairing_ctrl_val_handle;
    g_chr_defs[1].uuid = &kPairingDataUuid.u;
    g_chr_defs[1].access_cb = gatt_access_cb;
    g_chr_defs[1].flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_INDICATE;
    g_chr_defs[1].val_handle = &g_pairing_data_val_handle;

    memset(g_svc_defs, 0, sizeof(g_svc_defs));
    g_svc_defs[0].type = BLE_GATT_SVC_TYPE_PRIMARY;
    g_svc_defs[0].uuid = &kServiceUuid.u;
    g_svc_defs[0].characteristics = g_chr_defs;

    int rc = ble_gatts_count_cfg(g_svc_defs);
    if (rc != 0) {
        ESP_LOGW(kTag, "gatts_count_cfg failed rc=%d", rc);
        return false;
    }
    rc = ble_gatts_add_svcs(g_svc_defs);
    if (rc != 0) {
        ESP_LOGW(kTag, "gatts_add_svcs failed rc=%d", rc);
        return false;
    }
    return true;
}

bool ensure_ble_host_started()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool already_started = g_host_started;
    const bool failed = g_host_failed;
    if (!g_host_started) {
        g_host_started = true;
    }
    portEXIT_CRITICAL(&g_state_lock);
    if (failed) {
        return false;
    }
    if (already_started) {
        return true;
    }

    const esp_err_t init_rc = nimble_port_init();
    if (init_rc != ESP_OK) {
        ESP_LOGW(kTag, "nimble_port_init failed rc=%d", (int)init_rc);
        portENTER_CRITICAL(&g_state_lock);
        g_host_started = false;
        g_host_failed = true;
        portEXIT_CRITICAL(&g_state_lock);
        return false;
    }

    ble_svc_gap_init();
    ble_svc_gatt_init();
    if (!configure_gatt()) {
        portENTER_CRITICAL(&g_state_lock);
        g_host_failed = true;
        portEXIT_CRITICAL(&g_state_lock);
        return false;
    }

    int rc = ble_svc_gap_device_name_set(g_device_name);
    if (rc != 0) {
        ESP_LOGW(kTag, "device_name_set failed rc=%d", rc);
    }
    ble_att_set_preferred_mtu(kPreferredAttMtu);

    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    nimble_port_freertos_init(host_task);
    return true;
}

}  // namespace

bool local_transport_ble_configure(const LocalTransportBlePeripheralConfig& config)
{
    if (config.device_name == nullptr || config.device_name[0] == '\0' ||
        strlen(config.device_name) >= sizeof(g_device_name) ||
        config.inbound_frame == nullptr) {
        return false;
    }

    portENTER_CRITICAL(&g_state_lock);
    if (g_host_started || g_advertising_requested ||
        g_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        const bool unchanged =
            g_inbound_frame == config.inbound_frame &&
            strcmp(g_device_name, config.device_name) == 0;
        portEXIT_CRITICAL(&g_state_lock);
        return unchanged;
    }
    strlcpy(g_device_name, config.device_name, sizeof(g_device_name));
    g_inbound_frame = config.inbound_frame;
    clear_inbound_frame_locked();
    portEXIT_CRITICAL(&g_state_lock);
    return true;
}

bool local_transport_ble_start_pairing_advertising(const uint8_t fingerprint[8])
{
    if (fingerprint == nullptr || g_inbound_frame == nullptr || g_device_name[0] == '\0') {
        return false;
    }
    if (!ensure_ble_host_started()) {
        return false;
    }

    portENTER_CRITICAL(&g_state_lock);
    memcpy(g_advertised_fingerprint, fingerprint, kFingerprintBytes);
    g_advertising_requested = true;
    portEXIT_CRITICAL(&g_state_lock);

    return start_advertising_if_ready();
}

void local_transport_ble_stop_pairing_advertising()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool host_started = g_host_started;
    g_advertising_requested = false;
    g_advertising_restart_pending = false;
    g_next_advertising_retry_us = 0;
    portEXIT_CRITICAL(&g_state_lock);

    if (host_started && ble_gap_adv_active()) {
        const int rc = ble_gap_adv_stop();
        if (rc != 0 && rc != BLE_HS_EALREADY) {
            ESP_LOGW(kTag, "adv_stop failed rc=%d", rc);
        }
    }
    set_advertising_active(false);
}

void local_transport_ble_poll()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool restart_pending = g_advertising_restart_pending;
    const int64_t next_retry_us = g_next_advertising_retry_us;
    portEXIT_CRITICAL(&g_state_lock);
    if (restart_pending && esp_timer_get_time() >= next_retry_us) {
        start_advertising_if_ready();
    }
}

bool local_transport_ble_advertising()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool active = g_advertising_active || g_advertising_requested;
    portEXIT_CRITICAL(&g_state_lock);
    return active;
}

bool local_transport_ble_advertising_active()
{
    portENTER_CRITICAL(&g_state_lock);
    const bool active = g_advertising_active;
    portEXIT_CRITICAL(&g_state_lock);
    return active;
}

bool local_transport_ble_connected()
{
    return connection_handle() != BLE_HS_CONN_HANDLE_NONE;
}

void local_transport_ble_disconnect()
{
    const uint16_t conn = connection_handle();
    if (conn == BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    const int rc = ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
    if (rc != 0 && rc != BLE_HS_EALREADY && rc != BLE_HS_ENOTCONN) {
        ESP_LOGW(kTag, "disconnect failed conn=%u rc=%d", (unsigned)conn, rc);
    }
}

uint16_t local_transport_ble_current_att_mtu()
{
    return current_att_mtu_for_connection(connection_handle());
}

bool local_transport_ble_receive(LocalTransportBleInboundFrame* frame)
{
    if (frame == nullptr) {
        return false;
    }
    portENTER_CRITICAL(&g_state_lock);
    const bool pending = g_inbound_pending;
    if (pending) {
        if (g_inbound_frame == nullptr) {
            portEXIT_CRITICAL(&g_state_lock);
            return false;
        }
        *frame = *g_inbound_frame;
        clear_inbound_frame_locked();
    }
    portEXIT_CRITICAL(&g_state_lock);
    return pending;
}

bool local_transport_ble_send_indication(
    LocalTransportBleChannel channel,
    const uint8_t* payload,
    size_t payload_len)
{
    if ((payload_len > 0 && payload == nullptr) ||
        payload_len == 0 ||
        payload_len > kLocalTransportBleMaxPayloadBytes ||
        !indication_enabled_for_channel(channel)) {
        return false;
    }
    const uint16_t conn = connection_handle();
    const uint16_t value_handle = value_handle_for_channel(channel);
    if (conn == BLE_HS_CONN_HANDLE_NONE || value_handle == 0) {
        return false;
    }
    if (!begin_indication(conn, value_handle)) {
        ESP_LOGW(kTag, "indication already pending channel=%u", (unsigned)channel);
        return false;
    }
    os_mbuf* om = ble_hs_mbuf_from_flat(payload, static_cast<uint16_t>(payload_len));
    if (om == nullptr) {
        abandon_indication(conn, value_handle);
        return false;
    }
    const int rc = ble_gatts_indicate_custom(conn, value_handle, om);
    if (rc != 0) {
        abandon_indication(conn, value_handle);
        ESP_LOGW(kTag, "indicate failed channel=%u rc=%d", (unsigned)channel, rc);
        return false;
    }
    if (xSemaphoreTake(
            g_indication_completion,
            pdMS_TO_TICKS(kLocalTransportCarrierAckTimeoutMs)) != pdTRUE) {
        abandon_indication(conn, value_handle);
        ESP_LOGW(kTag, "indication ack timeout channel=%u", (unsigned)channel);
        return false;
    }
    const int status = indication_completion_status();
    if (status != BLE_HS_EDONE) {
        ESP_LOGW(kTag, "indication completion failed channel=%u status=%d",
                 (unsigned)channel, status);
        return false;
    }
    return true;
}

}  // namespace signing
