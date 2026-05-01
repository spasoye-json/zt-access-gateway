/**
 * POST /mfa/initiate request body.
 * No fields required — userId is extracted from the authenticated JWT in req.user (D-04).
 */
export class InitiateMfaDto {}
