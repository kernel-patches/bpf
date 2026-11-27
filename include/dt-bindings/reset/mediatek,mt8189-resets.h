/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Copyright (c) 2026 Collabora Ltd.
 * Author: Louis-Alexis Eyraud <louisalexis.eyraud@collabora.com>
 */

#ifndef _DT_BINDINGS_RESET_CONTROLLER_MT8189
#define _DT_BINDINGS_RESET_CONTROLLER_MT8189

/* UFS resets */
#define MT8189_UFSAO_RST_UFS_MPHY		0

#define MT8189_UFSPDN_RST_UFS_UNIPRO		0
#define MT8189_UFSPDN_RST_UFS_CRYPTO		1
#define MT8189_UFSPDN_RST_UFS_HCI		2

#endif  /* _DT_BINDINGS_RESET_CONTROLLER_MT8189 */
