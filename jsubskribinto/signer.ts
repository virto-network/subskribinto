import {
  decodeAddress,
  encodeAddress,
  base64Decode,
} from "@polkadot/util-crypto";

import { KeypairType } from "@polkadot/util-crypto/types";
import type { KeyringPair$Json } from "@polkadot/keyring/types";
import { getPolkadotSigner, type PolkadotSigner } from "@polkadot-api/signer";
import { createPair } from "@polkadot/keyring";
import { isHex, hexToU8a } from "npm:@polkadot/util";
import { ed25519CreateDerive } from "@polkadot-labs/hdkd";
import { mnemonicToMiniSecret } from "@polkadot-labs/hdkd-helpers";

export enum SiginigChoiceType {
  MNEMONIC = 1,
  SEED = 2,
  FILE = 4,
}

export type SigningChoice =
  | {
      type: SiginigChoiceType.MNEMONIC;
      phrase: string;
      derivePath?: string;
    }
  | {
      type: SiginigChoiceType.SEED;
      seed: Uint8Array;
    }
  | {
      type: SiginigChoiceType.FILE;
      file: Record<string, unknown>;
      passphrase: string;
    };

export function intoKeypair(signingChoice: SigningChoice): PolkadotSigner {
  switch (signingChoice.type) {
    case SiginigChoiceType.MNEMONIC: {
      const derive = ed25519CreateDerive(
        mnemonicToMiniSecret(signingChoice.phrase),
      );
      const pair = derive(signingChoice.derivePath ?? "");
      return getPolkadotSigner(pair.publicKey, "Sr25519", pair.sign);
    }
    case SiginigChoiceType.SEED: {
      throw new Error("Not implemented yet");
    }
    case SiginigChoiceType.FILE: {
      const json = signingChoice.file as unknown as KeyringPair$Json;

      const cryptoType = Array.isArray(json.encoding.content)
        ? json.encoding.content[1]
        : "ed25519";
      const encType = Array.isArray(json.encoding.type)
        ? json.encoding.type
        : [json.encoding.type];
      const pair = createPair(
        { toSS58: encodeAddress, type: cryptoType as KeypairType },
        { publicKey: decodeAddress(json.address, true) },
        json.meta,
        isHex(json.encoded)
          ? hexToU8a(json.encoded)
          : base64Decode(json.encoded),
        encType,
      );

      // unlock, save account and then lock (locking cleans secretKey, so needs to be last)
      pair.decodePkcs8(signingChoice.passphrase);

      return getPolkadotSigner(pair.publicKey, "Sr25519", pair.sign);
    }
  }
}
