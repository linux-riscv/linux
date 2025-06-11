/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KUnit Userspace testing API.
 *
 * Copyright (C) 2025, Linutronix GmbH.
 * Author: Thomas Weißschuh <thomas.weissschuh@linutronix.de>
 */

#ifndef _KUNIT_UAPI_H
#define _KUNIT_UAPI_H

struct blob;
struct kunit;

/**
 * kunit_uapi_run_kselftest() - Run a userspace kselftest as part of kunit
 * @test: The test context object.
 * @executable: kselftest executable to run
 *
 * Runs the kselftest and forwards its TAP output and exit status to kunit.
 */
void kunit_uapi_run_kselftest(struct kunit *test, const struct blob *executable);

#endif /* _KUNIT_UAPI_H */
