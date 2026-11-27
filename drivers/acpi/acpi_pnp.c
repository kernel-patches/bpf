// SPDX-License-Identifier: GPL-2.0-only
/*
 * ACPI support for PNP bus type
 *
 * Copyright (C) 2014, Intel Corporation
 * Authors: Zhang Rui <rui.zhang@intel.com>
 *          Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/ctype.h>

#include "internal.h"

static const struct acpi_device_id acpi_pnp_device_ids[] = {
	/* pata_isapnp */
	{ .id = "PNP0600" },		/* Generic ESDI/IDE/ATA compatible hard disk controller */
	/* floppy */
	{ .id = "PNP0700" },
	/* tpm_inf_pnp */
	{ .id = "IFX0101" },		/* Infineon TPMs */
	{ .id = "IFX0102" },		/* Infineon TPMs */
	/*tpm_tis */
	{ .id = "PNP0C31" },		/* TPM */
	{ .id = "ATM1200" },		/* Atmel */
	{ .id = "IFX0102" },		/* Infineon */
	{ .id = "BCM0101" },		/* Broadcom */
	{ .id = "BCM0102" },		/* Broadcom */
	{ .id = "NSC1200" },		/* National */
	{ .id = "ICO0102" },		/* Intel */
	/* ide   */
	{ .id = "PNP0600" },		/* Generic ESDI/IDE/ATA compatible hard disk controller */
	/* ns558 */
	{ .id = "ASB16fd" },		/* AdLib NSC16 */
	{ .id = "AZT3001" },		/* AZT1008 */
	{ .id = "CDC0001" },		/* Opl3-SAx */
	{ .id = "CSC0001" },		/* CS4232 */
	{ .id = "CSC000f" },		/* CS4236 */
	{ .id = "CSC0101" },		/* CS4327 */
	{ .id = "CTL7001" },		/* SB16 */
	{ .id = "CTL7002" },		/* AWE64 */
	{ .id = "CTL7005" },		/* Vibra16 */
	{ .id = "ENS2020" },		/* SoundscapeVIVO */
	{ .id = "ESS0001" },		/* ES1869 */
	{ .id = "ESS0005" },		/* ES1878 */
	{ .id = "ESS6880" },		/* ES688 */
	{ .id = "IBM0012" },		/* CS4232 */
	{ .id = "OPT0001" },		/* OPTi Audio16 */
	{ .id = "YMH0006" },		/* Opl3-SA */
	{ .id = "YMH0022" },		/* Opl3-SAx */
	{ .id = "PNPb02f" },		/* Generic */
	/* i8042 kbd */
	{ .id = "PNP0300" },
	{ .id = "PNP0301" },
	{ .id = "PNP0302" },
	{ .id = "PNP0303" },
	{ .id = "PNP0304" },
	{ .id = "PNP0305" },
	{ .id = "PNP0306" },
	{ .id = "PNP0309" },
	{ .id = "PNP030a" },
	{ .id = "PNP030b" },
	{ .id = "PNP0320" },
	{ .id = "PNP0343" },
	{ .id = "PNP0344" },
	{ .id = "PNP0345" },
	{ .id = "CPQA0D7" },
	/* i8042 aux */
	{ .id = "AUI0200" },
	{ .id = "FJC6000" },
	{ .id = "FJC6001" },
	{ .id = "PNP0f03" },
	{ .id = "PNP0f0b" },
	{ .id = "PNP0f0e" },
	{ .id = "PNP0f12" },
	{ .id = "PNP0f13" },
	{ .id = "PNP0f19" },
	{ .id = "PNP0f1c" },
	{ .id = "SYN0801" },
	/* fcpnp */
	{ .id = "AVM0900" },
	/* radio-cadet */
	{ .id = "MSM0c24" },		/* ADS Cadet AM/FM Radio Card */
	/* radio-gemtek */
	{ .id = "ADS7183" },		/* AOpen FX-3D/Pro Radio */
	/* radio-sf16fmr2 */
	{ .id = "MFRad13" },		/* tuner subdevice of SF16-FMD2 */
	/* ene_ir */
	{ .id = "ENE0100" },
	{ .id = "ENE0200" },
	{ .id = "ENE0201" },
	{ .id = "ENE0202" },
	/* fintek-cir */
	{ .id = "FIT0002" },		/* CIR */
	/* ite-cir */
	{ .id = "ITE8704" },		/* Default model */
	{ .id = "ITE8713" },		/* CIR found in EEEBox 1501U */
	{ .id = "ITE8708" },		/* Bridged IT8512 */
	{ .id = "ITE8709" },		/* SRAM-Bridged IT8512 */
	/* nuvoton-cir */
	{ .id = "WEC0530" },		/* CIR */
	{ .id = "NTN0530" },		/* CIR for new chip's pnp id */
	/* Winbond CIR */
	{ .id = "WEC1022" },
	/* wbsd */
	{ .id = "WEC0517" },
	{ .id = "WEC0518" },
	/* Winbond CIR */
	{ .id = "TCM5090" },		/* 3Com Etherlink III (TP) */
	{ .id = "TCM5091" },		/* 3Com Etherlink III */
	{ .id = "TCM5094" },		/* 3Com Etherlink III (combo) */
	{ .id = "TCM5095" },		/* 3Com Etherlink III (TPO) */
	{ .id = "TCM5098" },		/* 3Com Etherlink III (TPC) */
	{ .id = "PNP80f7" },		/* 3Com Etherlink III compatible */
	{ .id = "PNP80f8" },		/* 3Com Etherlink III compatible */
	/* nsc-ircc */
	{ .id = "NSC6001" },
	{ .id = "HWPC224" },
	{ .id = "IBM0071" },
	/* smsc-ircc2 */
	{ .id = "SMCf010" },
	/* parport_pc */
	{ .id = "PNP0400" },		/* Standard LPT Printer Port */
	{ .id = "PNP0401" },		/* ECP Printer Port */
	/* apple-gmux */
	{ .id = "APP000B" },
	/* c6xdigio */
	{ .id = "PNP0400" },		/* Standard LPT Printer Port */
	{ .id = "PNP0401" },		/* ECP Printer Port */
	/* ni_atmio.c */
	{ .id = "NIC1900" },
	{ .id = "NIC2400" },
	{ .id = "NIC2500" },
	{ .id = "NIC2600" },
	{ .id = "NIC2700" },
	/* serial */
	{ .id = "AAC000F" },		/* Archtek America Corp. Archtek SmartLink Modem 3334BT Plug & Play */
	{ .id = "ADC0001" },		/* Anchor Datacomm BV. SXPro 144 External Data Fax Modem Plug & Play */
	{ .id = "ADC0002" },		/* SXPro 288 External Data Fax Modem Plug & Play */
	{ .id = "AEI0250" },		/* PROLiNK 1456VH ISA PnP K56flex Fax Modem */
	{ .id = "AEI1240" },		/* Actiontec ISA PNP 56K X2 Fax Modem */
	{ .id = "AKY1021" },		/* Rockwell 56K ACF II Fax+Data+Voice Modem */
	{ .id = "ALI5123" },		/* ALi Fast Infrared Controller */
	{ .id = "AZT4001" },		/* AZT3005 PnP SOUND DEVICE */
	{ .id = "BDP3336" },		/* Best Data Products Inc. Smart One 336F PnP Modem */
	{ .id = "BRI0A49" },		/* Boca Complete Ofc Communicator 14.4 Data-FAX */
	{ .id = "BRI1400" },		/* Boca Research 33,600 ACF Modem */
	{ .id = "BRI3400" },		/* Boca 33.6 Kbps Internal FD34FSVD */
	{ .id = "CPI4050" },		/* Computer Peripherals Inc. EuroViVa CommCenter-33.6 SP PnP */
	{ .id = "CTL3001" },		/* Creative Labs Phone Blaster 28.8 DSVD PnP Voice */
	{ .id = "CTL3011" },		/* Creative Labs Modem Blaster 28.8 DSVD PnP Voice */
	{ .id = "DAV0336" },		/* Davicom ISA 33.6K Modem */
	{ .id = "DMB1032" },		/* Creative Modem Blaster Flash56 DI5601-1 */
	{ .id = "DMB2001" },		/* Creative Modem Blaster V.90 DI5660 */
	{ .id = "ETT0002" },		/* E-Tech CyberBULLET PC56RVP */
	{ .id = "FUJ0202" },		/* Fujitsu 33600 PnP-I2 R Plug & Play */
	{ .id = "FUJ0205" },		/* Fujitsu FMV-FX431 Plug & Play */
	{ .id = "FUJ0206" },		/* Fujitsu 33600 PnP-I4 R Plug & Play */
	{ .id = "FUJ0209" },		/* Fujitsu Fax Voice 33600 PNP-I5 R Plug & Play */
	{ .id = "GVC000F" },		/* Archtek SmartLink Modem 3334BT Plug & Play */
	{ .id = "GVC0303" },		/* Archtek SmartLink Modem 3334BRV 33.6K Data Fax Voice */
	{ .id = "HAY0001" },		/* Hayes Optima 288 V.34-V.FC + FAX + Voice Plug & Play */
	{ .id = "HAY000C" },		/* Hayes Optima 336 V.34 + FAX + Voice PnP */
	{ .id = "HAY000D" },		/* Hayes Optima 336B V.34 + FAX + Voice PnP */
	{ .id = "HAY5670" },		/* Hayes Accura 56K Ext Fax Modem PnP */
	{ .id = "HAY5674" },		/* Hayes Accura 56K Ext Fax Modem PnP */
	{ .id = "HAY5675" },		/* Hayes Accura 56K Fax Modem PnP */
	{ .id = "HAYF000" },		/* Hayes 288, V.34 + FAX */
	{ .id = "HAYF001" },		/* Hayes Optima 288 V.34 + FAX + Voice, Plug & Play */
	{ .id = "IBM0033" },		/* IBM Thinkpad 701 Internal Modem Voice */
	{ .id = "PNP4972" },		/* Intermec CV60 touchscreen port */
	{ .id = "IXDC801" },		/* Intertex 28k8 33k6 Voice EXT PnP */
	{ .id = "IXDC901" },		/* Intertex 33k6 56k Voice EXT PnP */
	{ .id = "IXDD801" },		/* Intertex 28k8 33k6 Voice SP EXT PnP */
	{ .id = "IXDD901" },		/* Intertex 33k6 56k Voice SP EXT PnP */
	{ .id = "IXDF401" },		/* Intertex 28k8 33k6 Voice SP INT PnP */
	{ .id = "IXDF801" },		/* Intertex 28k8 33k6 Voice SP EXT PnP */
	{ .id = "IXDF901" },		/* Intertex 33k6 56k Voice SP EXT PnP */
	{ .id = "KOR4522" },		/* KORTEX 28800 Externe PnP */
	{ .id = "KORF661" },		/* KXPro 33.6 Vocal ASVD PnP */
	{ .id = "LAS4040" },		/* LASAT Internet 33600 PnP */
	{ .id = "LAS4540" },		/* Lasat Safire 560 PnP */
	{ .id = "LAS5440" },		/* Lasat Safire 336  PnP */
	{ .id = "MNP0281" },		/* Microcom TravelPorte FAST V.34 Plug & Play */
	{ .id = "MNP0336" },		/* Microcom DeskPorte V.34 FAST or FAST+ Plug & Play */
	{ .id = "MNP0339" },		/* Microcom DeskPorte FAST EP 28.8 Plug & Play */
	{ .id = "MNP0342" },		/* Microcom DeskPorte 28.8P Plug & Play */
	{ .id = "MNP0500" },		/* Microcom DeskPorte FAST ES 28.8 Plug & Play */
	{ .id = "MNP0501" },		/* Microcom DeskPorte FAST ES 28.8 Plug & Play */
	{ .id = "MNP0502" },		/* Microcom DeskPorte 28.8S Internal Plug & Play */
	{ .id = "MOT1105" },		/* Motorola BitSURFR Plug & Play */
	{ .id = "MOT1111" },		/* Motorola TA210 Plug & Play */
	{ .id = "MOT1114" },		/* Motorola HMTA 200 (ISDN) Plug & Play */
	{ .id = "MOT1115" },		/* Motorola BitSURFR Plug & Play */
	{ .id = "MOT1190" },		/* Motorola Lifestyle 28.8 Internal */
	{ .id = "MOT1501" },		/* Motorola V.3400 Plug & Play */
	{ .id = "MOT1502" },		/* Motorola Lifestyle 28.8 V.34 Plug & Play */
	{ .id = "MOT1505" },		/* Motorola Power 28.8 V.34 Plug & Play */
	{ .id = "MOT1509" },		/* Motorola ModemSURFR External 28.8 Plug & Play */
	{ .id = "MOT150A" },		/* Motorola Premier 33.6 Desktop Plug & Play */
	{ .id = "MOT150F" },		/* Motorola VoiceSURFR 56K External PnP */
	{ .id = "MOT1510" },		/* Motorola ModemSURFR 56K External PnP */
	{ .id = "MOT1550" },		/* Motorola ModemSURFR 56K Internal PnP */
	{ .id = "MOT1560" },		/* Motorola ModemSURFR Internal 28.8 Plug & Play */
	{ .id = "MOT1580" },		/* Motorola Premier 33.6 Internal Plug & Play */
	{ .id = "MOT15B0" },		/* Motorola OnlineSURFR 28.8 Internal Plug & Play */
	{ .id = "MOT15F0" },		/* Motorola VoiceSURFR 56K Internal PnP */
	{ .id = "MVX00A1" },		/*  Deskline K56 Phone System PnP */
	{ .id = "MVX00F2" },		/* PC Rider K56 Phone System PnP */
	{ .id = "nEC8241" },		/* NEC 98NOTE SPEAKER PHONE FAX MODEM(33600bps) */
	{ .id = "PMC2430" },		/* Pace 56 Voice Internal Plug & Play Modem */
	{ .id = "PNP0500" },		/* Generic standard PC COM port     */
	{ .id = "PNP0501" },		/* Generic 16550A-compatible COM port */
	{ .id = "PNPC000" },		/* Compaq 14400 Modem */
	{ .id = "PNPC001" },		/* Compaq 2400/9600 Modem */
	{ .id = "PNPC031" },		/* Dial-Up Networking Serial Cable between 2 PCs */
	{ .id = "PNPC032" },		/* Dial-Up Networking Parallel Cable between 2 PCs */
	{ .id = "PNPC100" },		/* Standard 9600 bps Modem */
	{ .id = "PNPC101" },		/* Standard 14400 bps Modem */
	{ .id = "PNPC102" },		/* Standard 28800 bps Modem */
	{ .id = "PNPC103" },		/* Standard Modem */
	{ .id = "PNPC104" },		/* Standard 9600 bps Modem */
	{ .id = "PNPC105" },		/* Standard 14400 bps Modem */
	{ .id = "PNPC106" },		/* Standard 28800 bps Modem */
	{ .id = "PNPC107" },		/* Standard Modem */
	{ .id = "PNPC108" },		/* Standard 9600 bps Modem */
	{ .id = "PNPC109" },		/* Standard 14400 bps Modem */
	{ .id = "PNPC10A" },		/* Standard 28800 bps Modem */
	{ .id = "PNPC10B" },		/* Standard Modem */
	{ .id = "PNPC10C" },		/* Standard 9600 bps Modem */
	{ .id = "PNPC10D" },		/* Standard 14400 bps Modem */
	{ .id = "PNPC10E" },		/* Standard 28800 bps Modem */
	{ .id = "PNPC10F" },		/* Standard Modem */
	{ .id = "PNP2000" },		/* Standard PCMCIA Card Modem */
	{ .id = "ROK0030" },		/* Rockwell 33.6 DPF Internal PnP, Modular Technology 33.6 Internal PnP */
	{ .id = "ROK0100" },		/* KORTEX 14400 Externe PnP */
	{ .id = "ROK4120" },		/* Rockwell 28.8 */
	{ .id = "ROK4920" },		/* Viking 28.8 INTERNAL Fax+Data+Voice PnP */
	{ .id = "RSS00A0" },		/* Rockwell 33.6 DPF External PnP, BT Prologue 33.6 External PnP, Modular Technology 33.6 External PnP */
	{ .id = "RSS0262" },		/* Viking 56K FAX INT */
	{ .id = "RSS0250" },		/* K56 par,VV,Voice,Speakphone,AudioSpan,PnP */
	{ .id = "SUP1310" },		/* SupraExpress 28.8 Data/Fax PnP modem */
	{ .id = "SUP1381" },		/* SupraExpress 336i PnP Voice Modem */
	{ .id = "SUP1421" },		/* SupraExpress 33.6 Data/Fax PnP modem */
	{ .id = "SUP1590" },		/* SupraExpress 33.6 Data/Fax PnP modem */
	{ .id = "SUP1620" },		/* SupraExpress 336i Sp ASVD */
	{ .id = "SUP1760" },		/* SupraExpress 33.6 Data/Fax PnP modem */
	{ .id = "SUP2171" },		/* SupraExpress 56i Sp Intl */
	{ .id = "TEX0011" },		/* Phoebe Micro 33.6 Data Fax 1433VQH Plug & Play */
	{ .id = "UAC000F" },		/* Archtek SmartLink Modem 3334BT Plug & Play */
	{ .id = "USR0000" },		/* 3Com Corp. Gateway Telepath IIvi 33.6 */
	{ .id = "USR0002" },		/* U.S. Robotics Sporster 33.6K Fax INT PnP */
	{ .id = "USR0004" },		/*  Sportster Vi 14.4 PnP FAX Voicemail */
	{ .id = "USR0006" },		/* U.S. Robotics 33.6K Voice INT PnP */
	{ .id = "USR0007" },		/* U.S. Robotics 33.6K Voice EXT PnP */
	{ .id = "USR0009" },		/* U.S. Robotics Courier V.Everything INT PnP */
	{ .id = "USR2002" },		/* U.S. Robotics 33.6K Voice INT PnP */
	{ .id = "USR2070" },		/* U.S. Robotics 56K Voice INT PnP */
	{ .id = "USR2080" },		/* U.S. Robotics 56K Voice EXT PnP */
	{ .id = "USR3031" },		/* U.S. Robotics 56K FAX INT */
	{ .id = "USR3050" },		/* U.S. Robotics 56K FAX INT */
	{ .id = "USR3070" },		/* U.S. Robotics 56K Voice INT PnP */
	{ .id = "USR3080" },		/* U.S. Robotics 56K Voice EXT PnP */
	{ .id = "USR3090" },		/* U.S. Robotics 56K Voice INT PnP */
	{ .id = "USR9100" },		/* U.S. Robotics 56K Message  */
	{ .id = "USR9160" },		/* U.S. Robotics 56K FAX EXT PnP */
	{ .id = "USR9170" },		/* U.S. Robotics 56K FAX INT PnP */
	{ .id = "USR9180" },		/* U.S. Robotics 56K Voice EXT PnP */
	{ .id = "USR9190" },		/* U.S. Robotics 56K Voice INT PnP */
	{ .id = "WACFXXX" },		/* Wacom tablets */
	{ .id = "FPI2002" },		/* Compaq touchscreen */
	{ .id = "FUJ02B2" },		/* Fujitsu Stylistic touchscreens */
	{ .id = "FUJ02B3" },
	{ .id = "FUJ02B4" },		/* Fujitsu Stylistic LT touchscreens */
	{ .id = "FUJ02B6" },		/* Passive Fujitsu Stylistic touchscreens */
	{ .id = "FUJ02B7" },
	{ .id = "FUJ02B8" },
	{ .id = "FUJ02B9" },
	{ .id = "FUJ02BC" },
	{ .id = "FUJ02E5" },		/* Fujitsu Wacom Tablet PC device */
	{ .id = "FUJ02E6" },		/* Fujitsu P-series tablet PC device */
	{ .id = "FUJ02E7" },		/* Fujitsu Wacom 2FGT Tablet PC device */
	{ .id = "FUJ02E9" },		/* Fujitsu Wacom 1FGT Tablet PC device */
	{ .id = "LTS0001" },		/* LG C1 EXPRESS DUAL (C1-PB11A3) touch screen (actually a FUJ02E6 in disguise) */
	{ .id = "WCI0003" },		/* Rockwell's (PORALiNK) 33600 INT PNP */
	{ .id = "WEC1022" },		/* Winbond CIR port, should not be probed. We should keep track of it to prevent the legacy serial driver from probing it */
	/* scl200wdt */
	{ .id = "NSC0800" },		/* National Semiconductor PC87307/PC97307 watchdog component */
	/* mpu401 */
	{ .id = "PNPb006" },
	/* cs423x-pnpbios */
	{ .id = "CSC0100" },
	{ .id = "CSC0103" },
	{ .id = "CSC0110" },
	{ .id = "CSC0000" },
	{ .id = "GIM0100" },		/* Guillemot Turtlebeach something appears to be cs4232 compatible */
	/* es18xx-pnpbios */
	{ .id = "ESS1869" },
	{ .id = "ESS1879" },
	/* snd-opl3sa2-pnpbios */
	{ .id = "YMH0021" },
	{ .id = "NMX2210" },		/* Gateway Solo 2500 */
	{ }
};

static bool matching_id(const char *idstr, const char *list_id)
{
	int i;

	if (strlen(idstr) != strlen(list_id))
		return false;

	if (memcmp(idstr, list_id, 3))
		return false;

	for (i = 3; i < 7; i++) {
		char c = toupper(idstr[i]);

		if (!isxdigit(c)
		    || (list_id[i] != 'X' && c != toupper(list_id[i])))
			return false;
	}
	return true;
}

static bool acpi_pnp_match(const char *idstr, const struct acpi_device_id **matchid)
{
	const struct acpi_device_id *devid;

	for (devid = acpi_pnp_device_ids; devid->id[0]; devid++)
		if (matching_id(idstr, (char *)devid->id)) {
			if (matchid)
				*matchid = devid;

			return true;
		}

	return false;
}

static int acpi_pnp_attach(struct acpi_device *adev,
			   const struct acpi_device_id *id)
{
	return true;
}

static struct acpi_scan_handler acpi_pnp_handler = {
	.ids = acpi_pnp_device_ids,
	.match = acpi_pnp_match,
	.attach = acpi_pnp_attach,
};

bool acpi_is_pnp_device(struct acpi_device *adev)
{
	return adev->handler == &acpi_pnp_handler;
}
EXPORT_SYMBOL_GPL(acpi_is_pnp_device);

void __init acpi_pnp_init(void)
{
	acpi_scan_add_handler(&acpi_pnp_handler);
}
