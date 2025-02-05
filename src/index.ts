import { MasterID } from "./MasterID";
import { MemberID } from "./MemberID";
import type { Attestation, MasterIdentity, Identity, IdentityAttributes, PathPrefix, MemberIdentity } from "./interface";

export type { MasterIdentity as HDIdentity, MemberIdentity as SingleKeyIdentity, Attestation, Identity, IdentityAttributes, PathPrefix };
export { MasterID, MemberID };


// Added Identities type definition for import/export methods
type Identities = {
  lastIdPath: string;
  ids: Identity[];
};

/* Removed entire BAP class definition. All its functionality is now available via MasterID and MemberID. */