import { Binary, createClient } from "npm:polkadot-api";
import { SigningChoice, intoKeypair } from "./signer.ts";

import { getWsProvider } from "npm:polkadot-api/ws-provider/web";

export async function signAndSubmit(
  signingChoice: SigningChoice,
  callData: string,
  endpoint: string
) {
  const signer = intoKeypair(signingChoice);

  const client = createClient(getWsProvider(endpoint));

  const tx = await client
    .getUnsafeApi()
    .txFromCallData(Binary.fromHex(callData));

  console.log(`Submitting ${JSON.stringify(tx.decodedCall, null, 4)}`);

  const { txHash } = await tx.signAndSubmit(signer);

  console.log(`Transaction submitted with hash ${txHash}`);
  client.destroy();
  Deno.exit(0);
}
