// SPDX-License-Identifier: GPL-2.0

#include <linux/args.h>
#include <linux/blob.h>
#include <linux/stringify.h>

#define BLOB_SYMBOL_DATA	CONCATENATE(__blob_data_, BLOB_SYMBOL)
#define BLOB_SYMBOL_END		CONCATENATE(__blob_end_, BLOB_SYMBOL)

asm (
"	.pushsection .rodata, \"a\"\n"
"	.global " __stringify(BLOB_SYMBOL_DATA) "\n"
__stringify(BLOB_SYMBOL_DATA) ":\n"
"	.incbin \"" __stringify(BLOB_INPUT) "\"\n"
"	.global " __stringify(BLOB_SYMBOL_END) "\n"
__stringify(BLOB_SYMBOL_END) ":\n"
"	.popsection\n"
);

extern const u8 BLOB_SYMBOL_DATA;
extern const u8 BLOB_SYMBOL_END;

const struct blob CONCATENATE(__blob_, BLOB_SYMBOL) = {
	.path	= __stringify(BLOB_INPUT),
	.data	= &BLOB_SYMBOL_DATA,
	.end	= &BLOB_SYMBOL_END,
};
