/*
 * Patched bootp_print: add the missing ND_TCHECK bound check before the
 * EXTRACT_16BITS read of bp->bp_flags that CodeQL flagged and AFL++ crashed.
 * Used as the DEBUG_TEST_TCPDUMP patch fallback when the LLM is unavailable.
 */
void
bootp_print(netdissect_options *ndo,
            register const u_char *cp, u_int length)
{
	register const struct bootp *bp;

	bp = (const struct bootp *)cp;
	ND_TCHECK(bp->bp_op);

	/* FIX: bound-check the flags field before reading it. */
	ND_TCHECK2(bp->bp_flags, 2);
	if (EXTRACT_16BITS(&bp->bp_flags) & 0x8000)
		ND_PRINT((ndo, " [bootp broadcast]"));
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}
