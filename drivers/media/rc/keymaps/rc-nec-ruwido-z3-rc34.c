// SPDX-License-Identifier: GPL-2.0-or-later
//
// Keytable for the Ruwido Z3 RC-34 remote

#include <media/rc-map.h>
#include <linux/module.h>

static struct rc_map_table nec_ruwido_z3_rc34[] = {
	/* Ruwido Z3 RC-34, NECX address 0xe310 */
	{ 0xe3100f, KEY_POWER },
	{ 0xe31016, KEY_MENU },
	{ 0xe3100a, KEY_UP },
	{ 0xe3100b, KEY_DOWN },
	{ 0xe3100d, KEY_LEFT },
	{ 0xe3100c, KEY_RIGHT },
	{ 0xe31019, KEY_OK },
	{ 0xe3106a, KEY_BACK },
	{ 0xe31033, KEY_INFO },
	{ 0xe31066, KEY_DISPLAYTOGGLE },
	{ 0xe3101a, KEY_VOLUMEUP },
	{ 0xe31010, KEY_VOLUMEDOWN },
	{ 0xe31013, KEY_MUTE },
	{ 0xe31032, KEY_CHANNELUP },
	{ 0xe31031, KEY_CHANNELDOWN },
	{ 0xe31069, KEY_HP },
	{ 0xe31000, KEY_NUMERIC_1 },
	{ 0xe31001, KEY_NUMERIC_2 },
	{ 0xe31002, KEY_NUMERIC_3 },
	{ 0xe31003, KEY_NUMERIC_4 },
	{ 0xe31004, KEY_NUMERIC_5 },
	{ 0xe31005, KEY_NUMERIC_6 },
	{ 0xe31006, KEY_NUMERIC_7 },
	{ 0xe31007, KEY_NUMERIC_8 },
	{ 0xe31008, KEY_NUMERIC_9 },
	{ 0xe31030, KEY_NUMERIC_0 },
	{ 0xe31065, KEY_RED },
	{ 0xe31063, KEY_GREEN },
	{ 0xe31064, KEY_YELLOW },
	{ 0xe3106b, KEY_OPTION },
	{ 0xe31050, KEY_PLAY },
	{ 0xe31057, KEY_REWIND },
	{ 0xe31058, KEY_FASTFORWARD },
	{ 0xe31060, KEY_PROG1 },
	{ 0xe31061, KEY_PROG2 },
	{ 0xe31062, KEY_PROG3 },

	/* RC-34 remote volume keys */
	{ 0x3506, KEY_VOLUMEUP },
	{ 0x3507, KEY_VOLUMEDOWN },

	/* McIntosh HR070 remote volume keys */
	{ 0xca5542, KEY_VOLUMEUP },
	{ 0xca5543, KEY_VOLUMEDOWN },
};

static struct rc_map_list nec_ruwido_z3_rc34_map = {
	.map = {
		.scan     = nec_ruwido_z3_rc34,
		.entries  = ARRAY_SIZE(nec_ruwido_z3_rc34),
		.rc_proto = RC_PROTO_NECX,
		.name     = RC_MAP_NEC_RUWIDO_Z3_RC34,
	}
};

static int __init init_rc_map_nec_ruwido_z3_rc34(void)
{
	return rc_map_register(&nec_ruwido_z3_rc34_map);
}

static void __exit exit_rc_map_nec_ruwido_z3_rc34(void)
{
	rc_map_unregister(&nec_ruwido_z3_rc34_map);
}

module_init(init_rc_map_nec_ruwido_z3_rc34)
module_exit(exit_rc_map_nec_ruwido_z3_rc34)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabio Estevam <festevam@gmail.com>");
MODULE_DESCRIPTION("Ruwido Z3 RC-34 remote keytable");
