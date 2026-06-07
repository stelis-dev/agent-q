import { useEffect, useState } from "react";
import {
  DAppKitProvider,
  getWalletUniqueIdentifier,
  type UiWallet,
  useCurrentAccount,
  useCurrentClient,
  useCurrentNetwork,
  useCurrentWallet,
  useDAppKit,
} from "@mysten/dapp-kit-react";
import { ConnectButton } from "@mysten/dapp-kit-react/ui";
import { Transaction } from "@mysten/sui/transactions";
import { fromBase64 } from "@mysten/sui/utils";
import { AGENT_Q_SUI_WALLET_ID, AGENT_Q_SUI_WALLET_NAME } from "@stelis/agent-q-provider-sui/wallet-standard";
import { agentQProvider, dAppKit } from "./dapp-kit";
import "./style.css";

type AgentQTransferAction = {
  id: string;
  label: string;
  amountMist: string;
  gasBudgetMist: string;
  gasPriceMist: string;
};

type ExecuteTransactionResult = Awaited<ReturnType<ReturnType<typeof useCurrentClient>["executeTransaction"]>>;

const AGENT_Q_PERSONAL_MESSAGE = "Agent-Q dapp-kit personal message";
const AGENT_Q_TRANSFER_ACTIONS: AgentQTransferAction[] = [
  {
    id: "self-transfer-0-5-sui",
    label: "Self-transfer 0.5 SUI",
    amountMist: "500000000",
    gasBudgetMist: "10000000",
    gasPriceMist: "1000",
  },
  {
    id: "self-transfer-1-25-sui",
    label: "Self-transfer 1.25 SUI",
    amountMist: "1250000000",
    gasBudgetMist: "10000000",
    gasPriceMist: "1000",
  },
];

type SigningActionResult = {
  title: string;
  status: "success" | "error";
  lines: string[];
};

function shortValue(value: string): string {
  return value.length <= 28 ? value : `${value.slice(0, 18)}...${value.slice(-8)}`;
}

function isAgentQWallet(wallet: UiWallet | null | undefined): boolean {
  return wallet !== null && wallet !== undefined && getWalletUniqueIdentifier(wallet) === AGENT_Q_SUI_WALLET_ID;
}

function assertAgentQWalletSelected(wallet: UiWallet | null): void {
  if (!isAgentQWallet(wallet)) {
    throw new Error(`Select the ${AGENT_Q_SUI_WALLET_NAME} wallet before signing.`);
  }
}

function signingAuthorizationFromCapabilities(capabilities: Awaited<ReturnType<NonNullable<typeof agentQProvider>["getCapabilities"]>>): string {
  const signing = capabilities.signing;
  if (typeof signing !== "object" || signing === null || !("authorization" in signing)) {
    return "unknown";
  }
  const authorization = signing.authorization;
  return typeof authorization === "string" ? authorization : "unknown";
}

function createTransferTransaction(transfer: AgentQTransferAction, sender: string): Transaction {
  const transaction = new Transaction();
  transaction.setSender(sender);
  transaction.setGasBudget(transfer.gasBudgetMist);
  transaction.setGasPrice(transfer.gasPriceMist);
  const [coin] = transaction.splitCoins(transaction.gas, [BigInt(transfer.amountMist)]);
  transaction.transferObjects([coin], sender);
  return transaction;
}

function transactionFromExecutionResult(result: ExecuteTransactionResult) {
  return result.$kind === "Transaction" ? result.Transaction : result.FailedTransaction;
}

function executionStatusText(status: ReturnType<typeof transactionFromExecutionResult>["status"]): string {
  if (status.success) {
    return "success";
  }
  return `failed: ${status.error.message}`;
}

function WalletStatus() {
  const account = useCurrentAccount();
  const wallet = useCurrentWallet();
  const network = useCurrentNetwork();
  const client = useCurrentClient();
  const dAppKitInstance = useDAppKit();
  const [signingAuthorization, setSigningAuthorization] = useState("unavailable");
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [result, setResult] = useState<SigningActionResult | null>(null);
  const agentQWalletSelected = isAgentQWallet(wallet);
  const signingActionDisabled = pendingAction !== null || !agentQWalletSelected;
  const showUserModeActions = signingAuthorization === "user";
  const showPolicyModeActions = signingAuthorization === "policy";

  useEffect(() => {
    let cancelled = false;
    if (!account || agentQProvider === null) {
      setSigningAuthorization(agentQProvider === null ? "unavailable" : "not_connected");
      return () => {
        cancelled = true;
      };
    }
    if (!agentQWalletSelected) {
      setSigningAuthorization("agent_q_wallet_not_selected");
      return () => {
        cancelled = true;
      };
    }
    setSigningAuthorization("loading");
    agentQProvider.getCapabilities()
      .then((capabilities) => {
        if (!cancelled) {
          setSigningAuthorization(signingAuthorizationFromCapabilities(capabilities));
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setSigningAuthorization(error instanceof Error ? `error: ${error.message}` : "error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [account?.address, agentQWalletSelected]);

  async function runSigningAction(title: string, action: () => Promise<SigningActionResult>): Promise<void> {
    setPendingAction(title);
    setResult(null);
    try {
      setResult(await action());
    } catch (error) {
      setResult({
        title,
        status: "error",
        lines: [error instanceof Error ? error.message : String(error)],
      });
    } finally {
      setPendingAction(null);
    }
  }

  async function signTransfer(transfer: AgentQTransferAction): Promise<void> {
    await runSigningAction(transfer.label, async () => {
      assertAgentQWalletSelected(wallet);
      if (account === null) {
        throw new Error("Connect the Agent-Q wallet before signing.");
      }
      const signed = await dAppKitInstance.signTransaction({
        transaction: createTransferTransaction(transfer, account.address),
      });
      const executed = await client.executeTransaction({
        transaction: fromBase64(signed.bytes),
        signatures: [signed.signature],
        include: {
          effects: true,
          balanceChanges: true,
        },
      });
      const executedTransaction = transactionFromExecutionResult(executed);
      return {
        title: transfer.label,
        status: executedTransaction.status.success ? "success" : "error",
        lines: [
          `Self-transfer amount: ${transfer.amountMist} MIST`,
          `Execution digest: ${executedTransaction.digest}`,
          `Execution status: ${executionStatusText(executedTransaction.status)}`,
          `Signed bytes: ${signed.bytes.length} base64 chars`,
          `Signature: ${shortValue(signed.signature)}`,
        ],
      };
    });
  }

  async function signPersonalMessage(): Promise<void> {
    await runSigningAction("Personal message", async () => {
      assertAgentQWalletSelected(wallet);
      const signed = await dAppKitInstance.signPersonalMessage({
        message: new TextEncoder().encode(AGENT_Q_PERSONAL_MESSAGE),
      });
      return {
        title: "Personal message",
        status: "success",
        lines: [
          `Signed bytes: ${signed.bytes}`,
          `Signature: ${shortValue(signed.signature)}`,
        ],
      };
    });
  }

  if (!account) {
    return (
      <section className="panel">
        <h2>No wallet connected</h2>
        <p>Use the dapp-kit connect button to select the {AGENT_Q_SUI_WALLET_NAME} wallet.</p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2>Connected</h2>
      <dl>
        <dt>Wallet</dt>
        <dd>{wallet?.name ?? "Unknown"}</dd>
        <dt>Address</dt>
        <dd>{account.address}</dd>
        <dt>Network</dt>
        <dd>{network}</dd>
        <dt>Signing mode</dt>
        <dd>{signingAuthorization}</dd>
      </dl>
      {!agentQWalletSelected && (
        <p className="inline-warning">
          This example only signs through {AGENT_Q_SUI_WALLET_NAME}. Select that wallet before signing.
        </p>
      )}
      <section className="signing-grid" aria-label="Agent-Q signing actions">
        {(showUserModeActions || showPolicyModeActions) && AGENT_Q_TRANSFER_ACTIONS.map((transfer) => (
          <article className="signing-card" key={transfer.id}>
            <h3>{transfer.label}</h3>
            <p>
              Self-transfer {transfer.amountMist} MIST to {shortValue(account.address)}.
            </p>
            <button
              type="button"
              disabled={signingActionDisabled}
              onClick={() => void signTransfer(transfer)}
            >
              Sign self-transfer
            </button>
          </article>
        ))}
        {showUserModeActions && (
          <article className="signing-card">
            <h3>Personal message</h3>
            <p>{AGENT_Q_PERSONAL_MESSAGE}</p>
            <button
              type="button"
              disabled={signingActionDisabled}
              onClick={() => void signPersonalMessage()}
            >
              Sign personal message
            </button>
          </article>
        )}
        {!showUserModeActions && !showPolicyModeActions && (
          <article className="signing-card full-span">
            <h3>Signing actions unavailable</h3>
            <p>Waiting for Agent-Q signing mode before showing signing actions.</p>
          </article>
        )}
      </section>
      {pendingAction !== null && (
        <section className="result pending" aria-live="polite">
          Waiting for {pendingAction}...
        </section>
      )}
      {result !== null && (
        <section className={`result ${result.status}`} aria-live="polite">
          <h3>{result.title}</h3>
          <ul>
            {result.lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      )}
    </section>
  );
}

export function App() {
  return (
    <DAppKitProvider dAppKit={dAppKit}>
      <main>
        <header>
          <h1>Agent-Q Sui dapp-kit Example</h1>
          <ConnectButton modalOptions={{ filterFn: isAgentQWallet }} />
        </header>
        <WalletStatus />
      </main>
    </DAppKitProvider>
  );
}
