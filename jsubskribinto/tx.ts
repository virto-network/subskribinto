import { Binary, createClient } from "npm:polkadot-api";
import { SigningChoice, intoKeypair } from "./signer.ts";

import { getWsProvider } from "npm:polkadot-api/ws-provider/web";

export async function signAndSubmit(
  signingChoice: SigningChoice,
  callData: Binary,
  endpoint: string
) {
  const signer = intoKeypair(signingChoice);

  const client = createClient(getWsProvider(endpoint));

  const tx = await client.getUnsafeApi().txFromCallData(callData);

  console.log(
    `Submitting ${JSON.stringify(
      tx.decodedCall,
      (_, value) => {
        if (typeof value === "bigint") {
          return value.toLocaleString();
        } else {
          return value;
        }
      },
      4
    )}`
  );

  const { resolve, reject, promise } = Promise.withResolvers<void>();

  tx.signSubmitAndWatch(signer).subscribe({
    next(txEvent) {
      switch (txEvent.type) {
        case "signed":
          return console.log(`Call signed`);
        case "broadcasted":
          return console.log(
            `Transaction submitted with hash ${txEvent.txHash}`
          );
        case "txBestBlocksState":
          return console.log(`Transaction included in block`);
        case "finalized":
          return console.log(
            `Transaction finalized: ${txEvent.block.number}-${txEvent.block.index}`,
            txEvent.ok ? txEvent.events : txEvent.dispatchError
          );
      }
    },
    complete() {
      resolve();
    },
    error(e) {
      reject(e);
    },
  });

  await promise;

  client.destroy();
  Deno.exit(0);
}
