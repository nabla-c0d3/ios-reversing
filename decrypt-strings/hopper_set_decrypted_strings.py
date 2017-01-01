DECRYPTED_STRINGS = [
( 0x6a7b1d, ' AB_IIViewDeckController '),
( 0x6a7b35, ' toggleTopViewAnimated: '),
( 0x6a7b4c, ' AB_IIViewDeckController '),
( 0x6a7b64, ' openLeftViewBouncing: ')
]


doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()

for addr, decryptedString in DECRYPTED_STRINGS:
    seg.setInlineCommentAtAddress(addr, decryptedString)

