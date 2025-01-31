###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS Software H.323 Message Validation Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106305");
  script_cve_id("CVE-2016-6384");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco IOS Software H.323 Message Validation Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-h323");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the H.323 subsystem of Cisco IOS Software could allow an
unauthenticated, remote attacker to create a denial of service (DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to a failure to properly validate certain fields
in an H.323 protocol suite message. When processing the malicious message, the affected device may attempt to
access an invalid memory region, resulting in a crash.");

  script_tag(name:"impact", value:"An attacker who can submit an H.323 packet designed to trigger the
vulnerability could cause the affected device to crash and restart.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-09-29 14:55:00 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '12.2(15)B',
  '12.2(16)B',
  '12.2(16)B1',
  '12.2(16)B2',
  '12.2(16)BX',
  '12.2(16)BX1',
  '12.2(16)BX2',
  '12.2(16)BX3',
  '12.2(15)CZ',
  '12.2(15)CZ1',
  '12.2(15)CZ2',
  '12.2(15)CZ3',
  '12.2(15)MC1a',
  '12.2(15)MC1b',
  '12.2(15)MC1c',
  '12.2(15)MC2',
  '12.2(11)T',
  '12.2(11)T1',
  '12.2(11)T10',
  '12.2(11)T11',
  '12.2(11)T2',
  '12.2(11)T3',
  '12.2(11)T4',
  '12.2(11)T5',
  '12.2(11)T6',
  '12.2(11)T8',
  '12.2(11)T9',
  '12.2(13)T',
  '12.2(13)T1',
  '12.2(13)T1a',
  '12.2(13)T10',
  '12.2(13)T11',
  '12.2(13)T12',
  '12.2(13)T13',
  '12.2(13)T14',
  '12.2(13)T16',
  '12.2(13)T2',
  '12.2(13)T3',
  '12.2(13)T4',
  '12.2(13)T5',
  '12.2(13)T8',
  '12.2(13)T9',
  '12.2(15)T',
  '12.2(15)T1',
  '12.2(15)T10',
  '12.2(15)T11',
  '12.2(15)T12',
  '12.2(15)T13',
  '12.2(15)T14',
  '12.2(15)T15',
  '12.2(15)T16',
  '12.2(15)T2',
  '12.2(15)T4',
  '12.2(15)T4e',
  '12.2(15)T5',
  '12.2(15)T7',
  '12.2(15)T8',
  '12.2(15)T9',
  '12.2(4)YH',
  '12.2(8)YJ',
  '12.2(8)YJ1',
  '12.2(8)YL',
  '12.2(8)YM',
  '12.2(8)YN',
  '12.2(8)YN1',
  '12.2(11)YT',
  '12.2(11)YT1',
  '12.2(11)YT2',
  '12.2(11)YU',
  '12.2(11)YV',
  '12.2(11)ZC',
  '12.2(13)ZC',
  '12.2(13)ZD',
  '12.2(13)ZD1',
  '12.2(13)ZD2',
  '12.2(13)ZD3',
  '12.2(13)ZD4',
  '12.2(13)ZE',
  '12.2(13)ZF',
  '12.2(13)ZF1',
  '12.2(13)ZF2',
  '12.2(13)ZH',
  '12.2(13)ZH10',
  '12.2(13)ZH2',
  '12.2(13)ZH3',
  '12.2(13)ZH4',
  '12.2(13)ZH5',
  '12.2(13)ZH6',
  '12.2(13)ZH7',
  '12.2(13)ZH8',
  '12.2(13)ZH9',
  '12.2(15)ZJ',
  '12.2(15)ZJ1',
  '12.2(15)ZJ2',
  '12.2(15)ZJ3',
  '12.2(15)ZJ5',
  '12.2(15)ZL',
  '12.2(15)ZL1',
  '12.2(13)ZP',
  '12.2(13)ZP1',
  '12.2(13)ZP2',
  '12.2(13)ZP3',
  '12.2(13)ZP4',
  '12.3(1)',
  '12.3(1a)',
  '12.3(3)',
  '12.3(3a)',
  '12.3(3b)',
  '12.3(3c)',
  '12.3(3e)',
  '12.3(3f)',
  '12.3(3g)',
  '12.3(3h)',
  '12.3(3i)',
  '12.3(5)',
  '12.3(5a)',
  '12.3(5b)',
  '12.3(5c)',
  '12.3(5d)',
  '12.3(5e)',
  '12.3(5f)',
  '12.3(6)',
  '12.3(6a)',
  '12.3(6b)',
  '12.3(6c)',
  '12.3(6e)',
  '12.3(6f)',
  '12.3(9)',
  '12.3(9a)',
  '12.3(9b)',
  '12.3(9c)',
  '12.3(9d)',
  '12.3(9e)',
  '12.3(10)',
  '12.3(10a)',
  '12.3(10b)',
  '12.3(10c)',
  '12.3(10d)',
  '12.3(10e)',
  '12.3(10f)',
  '12.3(12)',
  '12.3(12a)',
  '12.3(12b)',
  '12.3(12c)',
  '12.3(12d)',
  '12.3(12e)',
  '12.3(13)',
  '12.3(13a)',
  '12.3(13b)',
  '12.3(15)',
  '12.3(15a)',
  '12.3(15b)',
  '12.3(16)',
  '12.3(16a)',
  '12.3(17)',
  '12.3(17a)',
  '12.3(17b)',
  '12.3(17c)',
  '12.3(18)',
  '12.3(18a)',
  '12.3(19)',
  '12.3(19a)',
  '12.3(20)',
  '12.3(20a)',
  '12.3(21)',
  '12.3(21b)',
  '12.3(22)',
  '12.3(22a)',
  '12.3(23)',
  '12.3(24)',
  '12.3(24a)',
  '12.3(25)',
  '12.3(26)',
  '12.3(1a)B',
  '12.3(3)B',
  '12.3(3)B1',
  '12.3(5a)B',
  '12.3(5a)B1',
  '12.3(5a)B2',
  '12.3(5a)B3',
  '12.3(5a)B4',
  '12.3(5a)B5',
  '12.3(2)T',
  '12.3(2)T1',
  '12.3(2)T2',
  '12.3(2)T3',
  '12.3(2)T4',
  '12.3(2)T5',
  '12.3(2)T6',
  '12.3(2)T7',
  '12.3(2)T8',
  '12.3(2)T9',
  '12.3(4)T',
  '12.3(4)T1',
  '12.3(4)T10',
  '12.3(4)T11',
  '12.3(4)T2',
  '12.3(4)T2a',
  '12.3(4)T3',
  '12.3(4)T4',
  '12.3(4)T6',
  '12.3(4)T7',
  '12.3(4)T8',
  '12.3(4)T9',
  '12.3(7)T',
  '12.3(7)T1',
  '12.3(7)T10',
  '12.3(7)T11',
  '12.3(7)T12',
  '12.3(7)T2',
  '12.3(7)T3',
  '12.3(7)T4',
  '12.3(7)T6',
  '12.3(7)T7',
  '12.3(7)T8',
  '12.3(7)T9',
  '12.3(8)T',
  '12.3(8)T1',
  '12.3(8)T10',
  '12.3(8)T11',
  '12.3(8)T3',
  '12.3(8)T4',
  '12.3(8)T5',
  '12.3(8)T6',
  '12.3(8)T7',
  '12.3(8)T8',
  '12.3(8)T9',
  '12.3(11)T',
  '12.3(11)T10',
  '12.3(11)T11',
  '12.3(11)T2',
  '12.3(11)T3',
  '12.3(11)T4',
  '12.3(11)T5',
  '12.3(11)T6',
  '12.3(11)T7',
  '12.3(11)T8',
  '12.3(11)T9',
  '12.3(14)T',
  '12.3(14)T1',
  '12.3(14)T2',
  '12.3(14)T3',
  '12.3(14)T5',
  '12.3(14)T6',
  '12.3(14)T7',
  '12.3(4)TPC11a',
  '12.3(4)TPC11b',
  '12.3(2)XA',
  '12.3(2)XA1',
  '12.3(2)XA2',
  '12.3(2)XA3',
  '12.3(2)XA4',
  '12.3(2)XA5',
  '12.3(2)XA6',
  '12.3(2)XA7',
  '12.3(2)XB',
  '12.3(2)XB1',
  '12.3(2)XB3',
  '12.3(2)XC',
  '12.3(2)XC1',
  '12.3(2)XC2',
  '12.3(2)XC3',
  '12.3(2)XC4',
  '12.3(2)XC5',
  '12.3(4)XD',
  '12.3(4)XD1',
  '12.3(4)XD2',
  '12.3(4)XD3',
  '12.3(4)XD4',
  '12.3(2)XE',
  '12.3(2)XE1',
  '12.3(2)XE2',
  '12.3(2)XE3',
  '12.3(2)XE4',
  '12.3(2)XE5',
  '12.3(2)XF',
  '12.3(4)XG',
  '12.3(4)XG1',
  '12.3(4)XG2',
  '12.3(4)XG3',
  '12.3(4)XG4',
  '12.3(4)XG5',
  '12.3(7)XI10a',
  '12.3(7)XI2',
  '12.3(7)XI3',
  '12.3(7)XI4',
  '12.3(7)XI5',
  '12.3(7)XI6',
  '12.3(7)XI7',
  '12.3(7)XI7a',
  '12.3(7)XI7b',
  '12.3(7)XI8',
  '12.3(7)XJ',
  '12.3(7)XJ1',
  '12.3(7)XJ2',
  '12.3(4)XK',
  '12.3(4)XK1',
  '12.3(4)XK2',
  '12.3(4)XK3',
  '12.3(4)XK4',
  '12.3(11)XL',
  '12.3(11)XL1',
  '12.3(4)XQ',
  '12.3(4)XQ1',
  '12.3(7)XR',
  '12.3(7)XR2',
  '12.3(7)XR3',
  '12.3(7)XR4',
  '12.3(7)XR5',
  '12.3(7)XR6',
  '12.3(7)XR7',
  '12.3(7)XS',
  '12.3(7)XS1',
  '12.3(7)XS2',
  '12.3(8)XU2',
  '12.3(8)XU3',
  '12.3(8)XU4',
  '12.3(8)XU5',
  '12.3(8)XW',
  '12.3(8)XW1',
  '12.3(8)XW2',
  '12.3(8)XW3',
  '12.3(8)XX',
  '12.3(8)XX1',
  '12.3(8)XX2d',
  '12.3(8)XY',
  '12.3(8)XY1',
  '12.3(8)XY2',
  '12.3(8)XY3',
  '12.3(8)XY4',
  '12.3(8)XY5',
  '12.3(8)XY6',
  '12.3(8)XY7',
  '12.3(2)XZ1',
  '12.3(2)XZ2',
  '12.3(8)YA',
  '12.3(8)YA1',
  '12.3(8)YD',
  '12.3(8)YD1',
  '12.3(11)YF',
  '12.3(11)YF1',
  '12.3(11)YF2',
  '12.3(11)YF3',
  '12.3(11)YF4',
  '12.3(8)YG',
  '12.3(8)YG1',
  '12.3(8)YG2',
  '12.3(8)YG3',
  '12.3(8)YG4',
  '12.3(8)YG5',
  '12.3(8)YG6',
  '12.3(8)YH',
  '12.3(8)YI1',
  '12.3(8)YI2',
  '12.3(8)YI3',
  '12.3(11)YK',
  '12.3(11)YK1',
  '12.3(11)YK2',
  '12.3(11)YK3',
  '12.3(14)YM10',
  '12.3(14)YM11',
  '12.3(14)YM12',
  '12.3(14)YM13',
  '12.3(14)YM2',
  '12.3(14)YM3',
  '12.3(14)YM4',
  '12.3(14)YM5',
  '12.3(14)YM6',
  '12.3(14)YM7',
  '12.3(14)YM8',
  '12.3(14)YM9',
  '12.3(14)YQ',
  '12.3(14)YQ1',
  '12.3(14)YQ2',
  '12.3(14)YQ3',
  '12.3(14)YQ4',
  '12.3(14)YQ5',
  '12.3(14)YQ6',
  '12.3(14)YQ7',
  '12.3(14)YQ8',
  '12.3(11)YS',
  '12.3(11)YS1',
  '12.3(11)YS2',
  '12.3(14)YT',
  '12.3(14)YT1',
  '12.3(14)YU',
  '12.3(14)YU1',
  '12.3(11)YZ',
  '12.3(11)YZ1',
  '12.3(11)YZ2',
  '12.3(8)ZA',
  '12.4(1)',
  '12.4(1a)',
  '12.4(1b)',
  '12.4(1c)',
  '12.4(3)',
  '12.4(3a)',
  '12.4(3b)',
  '12.4(3c)',
  '12.4(3d)',
  '12.4(3e)',
  '12.4(3f)',
  '12.4(3g)',
  '12.4(3h)',
  '12.4(3i)',
  '12.4(3j)',
  '12.4(5)',
  '12.4(5a)',
  '12.4(5b)',
  '12.4(5c)',
  '12.4(7)',
  '12.4(7a)',
  '12.4(7b)',
  '12.4(7c)',
  '12.4(7d)',
  '12.4(7e)',
  '12.4(7f)',
  '12.4(7g)',
  '12.4(7h)',
  '12.4(8)',
  '12.4(8a)',
  '12.4(8b)',
  '12.4(8c)',
  '12.4(8d)',
  '12.4(10)',
  '12.4(10a)',
  '12.4(10b)',
  '12.4(10c)',
  '12.4(12)',
  '12.4(12a)',
  '12.4(12b)',
  '12.4(12c)',
  '12.4(13)',
  '12.4(13a)',
  '12.4(13b)',
  '12.4(13c)',
  '12.4(13d)',
  '12.4(13e)',
  '12.4(13f)',
  '12.4(16)',
  '12.4(16a)',
  '12.4(16b)',
  '12.4(17)',
  '12.4(17a)',
  '12.4(17b)',
  '12.4(18)',
  '12.4(18a)',
  '12.4(18b)',
  '12.4(18c)',
  '12.4(18e)',
  '12.4(19)',
  '12.4(21)',
  '12.4(21a)',
  '12.4(23)',
  '12.4(23a)',
  '12.4(23b)',
  '12.4(25)',
  '12.4(25a)',
  '12.4(25b)',
  '12.4(25c)',
  '12.4(25d)',
  '12.4(25e)',
  '12.4(25f)',
  '12.4(25g)',
  '12.4(22)GC1',
  '12.4(24)GC1',
  '12.4(24)GC3',
  '12.4(24)GC3a',
  '12.4(24)GC4',
  '12.4(24)GC5',
  '12.4(2)MR',
  '12.4(2)MR1',
  '12.4(4)MR',
  '12.4(4)MR1',
  '12.4(6)MR',
  '12.4(6)MR1',
  '12.4(9)MR',
  '12.4(11)MR',
  '12.4(12)MR',
  '12.4(12)MR1',
  '12.4(12)MR2',
  '12.4(16)MR',
  '12.4(16)MR1',
  '12.4(16)MR2',
  '12.4(19)MR',
  '12.4(19)MR1',
  '12.4(19)MR2',
  '12.4(19)MR3',
  '12.4(20)MR',
  '12.4(20)MR2',
  '12.4(20)MRB',
  '12.4(20)MRB1',
  '12.4(11)SW',
  '12.4(11)SW1',
  '12.4(11)SW2',
  '12.4(11)SW3',
  '12.4(15)SW',
  '12.4(15)SW1',
  '12.4(15)SW2',
  '12.4(15)SW3',
  '12.4(15)SW4',
  '12.4(15)SW5',
  '12.4(15)SW6',
  '12.4(15)SW7',
  '12.4(15)SW8',
  '12.4(15)SW8a',
  '12.4(15)SW9',
  '12.4(2)T',
  '12.4(2)T1',
  '12.4(2)T2',
  '12.4(2)T3',
  '12.4(2)T4',
  '12.4(2)T5',
  '12.4(2)T6',
  '12.4(4)T',
  '12.4(4)T1',
  '12.4(4)T2',
  '12.4(4)T3',
  '12.4(4)T4',
  '12.4(4)T5',
  '12.4(4)T6',
  '12.4(4)T7',
  '12.4(4)T8',
  '12.4(6)T',
  '12.4(6)T1',
  '12.4(6)T10',
  '12.4(6)T11',
  '12.4(6)T2',
  '12.4(6)T3',
  '12.4(6)T4',
  '12.4(6)T5',
  '12.4(6)T6',
  '12.4(6)T7',
  '12.4(6)T8',
  '12.4(6)T9',
  '12.4(9)T',
  '12.4(9)T1',
  '12.4(9)T2',
  '12.4(9)T3',
  '12.4(9)T4',
  '12.4(9)T5',
  '12.4(9)T6',
  '12.4(9)T7',
  '12.4(11)T',
  '12.4(11)T1',
  '12.4(11)T2',
  '12.4(11)T3',
  '12.4(11)T4',
  '12.4(15)T',
  '12.4(15)T1',
  '12.4(15)T10',
  '12.4(15)T11',
  '12.4(15)T12',
  '12.4(15)T13',
  '12.4(15)T14',
  '12.4(15)T15',
  '12.4(15)T16',
  '12.4(15)T17',
  '12.4(15)T2',
  '12.4(15)T3',
  '12.4(15)T4',
  '12.4(15)T5',
  '12.4(15)T6',
  '12.4(15)T7',
  '12.4(15)T8',
  '12.4(15)T9',
  '12.4(20)T',
  '12.4(20)T1',
  '12.4(20)T2',
  '12.4(20)T3',
  '12.4(20)T4',
  '12.4(20)T5',
  '12.4(20)T6',
  '12.4(22)T',
  '12.4(22)T1',
  '12.4(22)T2',
  '12.4(22)T3',
  '12.4(22)T4',
  '12.4(22)T5',
  '12.4(24)T',
  '12.4(24)T1',
  '12.4(24)T2',
  '12.4(24)T3',
  '12.4(24)T4',
  '12.4(24)T5',
  '12.4(24)T6',
  '12.4(24)T7',
  '12.4(24)T8',
  '12.4(2)XA',
  '12.4(2)XA1',
  '12.4(2)XA2',
  '12.4(2)XB',
  '12.4(2)XB1',
  '12.4(2)XB10',
  '12.4(2)XB11',
  '12.4(2)XB2',
  '12.4(2)XB3',
  '12.4(2)XB4',
  '12.4(2)XB5',
  '12.4(2)XB6',
  '12.4(2)XB7',
  '12.4(2)XB8',
  '12.4(2)XB9',
  '12.4(4)XC',
  '12.4(4)XC1',
  '12.4(4)XC2',
  '12.4(4)XC3',
  '12.4(4)XC4',
  '12.4(4)XC5',
  '12.4(4)XC6',
  '12.4(4)XC7',
  '12.4(4)XD',
  '12.4(4)XD1',
  '12.4(4)XD10',
  '12.4(4)XD11',
  '12.4(4)XD12',
  '12.4(4)XD2',
  '12.4(4)XD4',
  '12.4(4)XD5',
  '12.4(4)XD7',
  '12.4(4)XD8',
  '12.4(4)XD9',
  '12.4(6)XE',
  '12.4(6)XE1',
  '12.4(6)XE2',
  '12.4(6)XE3',
  '12.4(15)XF',
  '12.4(9)XG2',
  '12.4(11)XJ',
  '12.4(11)XJ2',
  '12.4(11)XJ3',
  '12.4(11)XJ4',
  '12.4(14)XK',
  '12.4(15)XL',
  '12.4(15)XL1',
  '12.4(15)XL2',
  '12.4(15)XL3',
  '12.4(15)XL4',
  '12.4(15)XL5',
  '12.4(15)XM1',
  '12.4(15)XM2',
  '12.4(6)XP',
  '12.4(6)XT',
  '12.4(6)XT1',
  '12.4(6)XT2',
  '12.4(11)XV',
  '12.4(11)XV1',
  '12.4(11)XW',
  '12.4(11)XW1',
  '12.4(11)XW10',
  '12.4(11)XW2',
  '12.4(11)XW3',
  '12.4(11)XW4',
  '12.4(11)XW5',
  '12.4(11)XW6',
  '12.4(11)XW7',
  '12.4(11)XW8',
  '12.4(11)XW9',
  '12.4(15)XY',
  '12.4(15)XY1',
  '12.4(15)XY2',
  '12.4(15)XY3',
  '12.4(15)XY4',
  '12.4(15)XY5',
  '12.4(15)XZ',
  '12.4(15)XZ1',
  '12.4(15)XZ2',
  '12.4(20)YA',
  '12.4(20)YA1',
  '12.4(20)YA2',
  '12.4(20)YA3',
  '12.4(22)YB',
  '12.4(22)YB1',
  '12.4(22)YB2',
  '12.4(22)YB3',
  '12.4(22)YB4',
  '12.4(22)YB5',
  '12.4(22)YB6',
  '12.4(22)YB7',
  '12.4(22)YB8',
  '15.0(1)M',
  '15.0(1)M1',
  '15.0(1)M10',
  '15.0(1)M2',
  '15.0(1)M3',
  '15.0(1)M4',
  '15.0(1)M5',
  '15.0(1)M6',
  '15.0(1)M7',
  '15.0(1)M8',
  '15.0(1)M9',
  '15.0(1)S',
  '15.0(1)S1',
  '15.0(1)S2',
  '15.0(1)S3a',
  '15.0(1)S4',
  '15.0(1)S4a',
  '15.0(1)S5',
  '15.0(1)S6',
  '15.0(1)XA',
  '15.0(1)XA1',
  '15.0(1)XA2',
  '15.0(1)XA3',
  '15.0(1)XA4',
  '15.0(1)XA5',
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.1(2)GC2',
  '15.1(4)GC',
  '15.1(4)GC1',
  '15.1(4)GC2',
  '15.1(4)M',
  '15.1(4)M1',
  '15.1(4)M10',
  '15.1(4)M2',
  '15.1(4)M3',
  '15.1(4)M3a',
  '15.1(4)M4',
  '15.1(4)M5',
  '15.1(4)M6',
  '15.1(4)M7',
  '15.1(4)M8',
  '15.1(4)M9',
  '15.1(1)S',
  '15.1(1)S1',
  '15.1(1)S2',
  '15.1(2)S',
  '15.1(2)S1',
  '15.1(2)S2',
  '15.1(3)S',
  '15.1(3)S0a',
  '15.1(3)S1',
  '15.1(3)S2',
  '15.1(3)S3',
  '15.1(3)S4',
  '15.1(3)S5',
  '15.1(3)S6',
  '15.1(1)T',
  '15.1(1)T1',
  '15.1(1)T2',
  '15.1(1)T3',
  '15.1(1)T4',
  '15.1(1)T5',
  '15.1(2)T',
  '15.1(2)T0a',
  '15.1(2)T1',
  '15.1(2)T2',
  '15.1(2)T2a',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(2)T5',
  '15.1(3)T',
  '15.1(3)T1',
  '15.1(3)T2',
  '15.1(3)T3',
  '15.1(3)T4',
  '15.1(1)XB',
  '15.2(1)GC',
  '15.2(1)GC1',
  '15.2(1)GC2',
  '15.2(2)GC',
  '15.2(3)GC',
  '15.2(3)GC1',
  '15.2(4)GC',
  '15.2(4)GC1',
  '15.2(4)GC2',
  '15.2(4)GC3',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M10',
  '15.2(4)M2',
  '15.2(4)M3',
  '15.2(4)M4',
  '15.2(4)M5',
  '15.2(4)M6',
  '15.2(4)M6a',
  '15.2(4)M7',
  '15.2(4)M8',
  '15.2(4)M9',
  '15.2(1)S',
  '15.2(1)S1',
  '15.2(1)S2',
  '15.2(2)S',
  '15.2(2)S1',
  '15.2(2)S2',
  '15.2(4)S',
  '15.2(4)S1',
  '15.2(4)S2',
  '15.2(4)S3',
  '15.2(4)S3a',
  '15.2(4)S4',
  '15.2(4)S4a',
  '15.2(4)S5',
  '15.2(4)S6',
  '15.2(4)S7',
  '15.2(1)T',
  '15.2(1)T1',
  '15.2(1)T2',
  '15.2(1)T3',
  '15.2(1)T3a',
  '15.2(1)T4',
  '15.2(2)T',
  '15.2(2)T1',
  '15.2(2)T2',
  '15.2(2)T3',
  '15.2(2)T4',
  '15.2(3)T',
  '15.2(3)T1',
  '15.2(3)T2',
  '15.2(3)T3',
  '15.2(3)T4',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.3(3)M3',
  '15.3(3)M4',
  '15.3(3)M5',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(1)S',
  '15.3(1)S1',
  '15.3(1)S2',
  '15.3(2)S',
  '15.3(2)S0a',
  '15.3(2)S1',
  '15.3(2)S2',
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S6',
  '15.3(3)S7',
  '15.3(1)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)T',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.4(1)CG',
  '15.4(1)CG1',
  '15.4(2)CG',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(1)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(1)S3',
  '15.4(1)S4',
  '15.4(2)S',
  '15.4(2)S1',
  '15.4(2)S2',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S',
  '15.4(3)S1',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(1)T',
  '15.4(1)T1',
  '15.4(1)T2',
  '15.4(1)T3',
  '15.4(1)T4',
  '15.4(2)T',
  '15.4(2)T1',
  '15.4(2)T2',
  '15.4(2)T3',
  '15.4(2)T4',
  '15.5(3)M',
  '15.5(3)M0a',
  '15.5(3)M1',
  '15.5(3)M2',
  '15.5(1)S',
  '15.5(1)S1',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)S3',
  '15.5(3)S',
  '15.5(3)S0a',
  '15.5(3)S1',
  '15.5(3)S2',
  '15.5(1)T4',
  '15.5(1)T',
  '15.5(1)T1',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.6(1)S',
  '15.6(1)T',
  '15.6(1)T0a' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );

