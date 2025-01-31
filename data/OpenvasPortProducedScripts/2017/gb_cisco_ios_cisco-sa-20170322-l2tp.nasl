###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS Software Layer 2 Tunneling Protocol Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106686");
  script_cve_id("CVE-2017-3857");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco IOS Software Layer 2 Tunneling Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Layer 2 Tunneling Protocol (L2TP) parsing function
of Cisco IOS Software could allow an unauthenticated, remote attacker to cause an affected device to reload.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of L2TP packets. An
attacker could exploit this vulnerability by sending a crafted L2TP packet to an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the affected device
to reload, resulting in a denial of service (DoS) condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-23 10:02:11 +0700 (Thu, 23 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '12.0(33)S',
  '12.0(33)S1',
  '12.0(33)S10',
  '12.0(33)S11',
  '12.0(33)S2',
  '12.0(33)S3',
  '12.0(33)S4',
  '12.0(33)S5',
  '12.0(33)S6',
  '12.0(33)S7',
  '12.0(33)S8',
  '12.0(33)S9',
  '12.2(33)CX',
  '12.2(33)CY',
  '12.2(33)CY1',
  '12.2(33)IRA',
  '12.2(33)IRB',
  '12.2(33)IRC',
  '12.2(33)IRD',
  '12.2(33)IRE',
  '12.2(33)IRE1',
  '12.2(33)IRE2',
  '12.2(33)IRF',
  '12.2(33)IRG',
  '12.2(33)IRG1',
  '12.2(33)IRH',
  '12.2(33)IRH1',
  '12.2(33)IRI',
  '12.2(33)MRA',
  '12.2(33)MRB',
  '12.2(33)MRB1',
  '12.2(33)MRB2',
  '12.2(33)MRB3',
  '12.2(33)MRB4',
  '12.2(33)MRB5',
  '12.2(33)MRB6',
  '12.2(33)SB',
  '12.2(33)SB1',
  '12.2(33)SB10',
  '12.2(33)SB11',
  '12.2(33)SB12',
  '12.2(33)SB13',
  '12.2(33)SB14',
  '12.2(33)SB15',
  '12.2(33)SB16',
  '12.2(33)SB17',
  '12.2(33)SB2',
  '12.2(33)SB3',
  '12.2(33)SB4',
  '12.2(33)SB5',
  '12.2(33)SB6',
  '12.2(33)SB7',
  '12.2(33)SB8',
  '12.2(33)SB9',
  '12.2(33)SCA',
  '12.2(33)SCA1',
  '12.2(33)SCA2',
  '12.2(33)SCB',
  '12.2(33)SCB1',
  '12.2(33)SCB10',
  '12.2(33)SCB11',
  '12.2(33)SCB2',
  '12.2(33)SCB3',
  '12.2(33)SCB4',
  '12.2(33)SCB5',
  '12.2(33)SCB6',
  '12.2(33)SCB7',
  '12.2(33)SCB8',
  '12.2(33)SCB9',
  '12.2(33)SCC',
  '12.2(33)SCC1',
  '12.2(33)SCC2',
  '12.2(33)SCC3',
  '12.2(33)SCC4',
  '12.2(33)SCC5',
  '12.2(33)SCC6',
  '12.2(33)SCC7',
  '12.2(33)SCD',
  '12.2(33)SCD1',
  '12.2(33)SCD2',
  '12.2(33)SCD3',
  '12.2(33)SCD4',
  '12.2(33)SCD5',
  '12.2(33)SCD6',
  '12.2(33)SCD7',
  '12.2(33)SCD8',
  '12.2(33)SCE',
  '12.2(33)SCE1',
  '12.2(33)SCE2',
  '12.2(33)SCE3',
  '12.2(33)SCE4',
  '12.2(33)SCE5',
  '12.2(33)SCE6',
  '12.2(33)SCF',
  '12.2(33)SCF1',
  '12.2(33)SCF2',
  '12.2(33)SCF3',
  '12.2(33)SCF4',
  '12.2(33)SCF5',
  '12.2(33)SCG',
  '12.2(33)SCG1',
  '12.2(33)SCG2',
  '12.2(33)SCG3',
  '12.2(33)SCG4',
  '12.2(33)SCG5',
  '12.2(33)SCG6',
  '12.2(33)SCG7',
  '12.2(33)SCH',
  '12.2(33)SCH0a',
  '12.2(33)SCH1',
  '12.2(33)SCH2',
  '12.2(33)SCH2a',
  '12.2(33)SCH3',
  '12.2(33)SCH4',
  '12.2(33)SCH5',
  '12.2(33)SCH6',
  '12.2(33)SCI',
  '12.2(33)SCI1',
  '12.2(33)SCI1a',
  '12.2(33)SCI2',
  '12.2(33)SCI2a',
  '12.2(33)SCI3',
  '12.2(33)SCJ',
  '12.2(33)SCJ1a',
  '12.2(33)SCJ2',
  '12.2(33)SCJ2a',
  '12.2(33)SRB',
  '12.2(33)SRC',
  '12.2(33)SRC1',
  '12.2(33)SRC2',
  '12.2(33)SRC3',
  '12.2(33)SRC4',
  '12.2(33)SRC5',
  '12.2(33)SRC6',
  '12.2(33)SRD',
  '12.2(33)SRD1',
  '12.2(33)SRD2',
  '12.2(33)SRD2a',
  '12.2(33)SRD3',
  '12.2(33)SRD4',
  '12.2(33)SRD5',
  '12.2(33)SRD6',
  '12.2(33)SRD7',
  '12.2(33)SRD8',
  '12.2(33)SRE',
  '12.2(33)SRE0a',
  '12.2(33)SRE1',
  '12.2(33)SRE10',
  '12.2(33)SRE11',
  '12.2(33)SRE12',
  '12.2(33)SRE13',
  '12.2(33)SRE14',
  '12.2(33)SRE15',
  '12.2(33)SRE2',
  '12.2(33)SRE3',
  '12.2(33)SRE4',
  '12.2(33)SRE5',
  '12.2(33)SRE6',
  '12.2(33)SRE7',
  '12.2(33)SRE7a',
  '12.2(33)SRE8',
  '12.2(33)SRE9',
  '12.2(33)SRE9a',
  '12.2(33)XN1',
  '12.2(37)SE',
  '12.2(37)SE1',
  '12.2(37)SG1',
  '12.2(40)SE',
  '12.2(44)SE',
  '12.2(44)SE1',
  '12.2(44)SE2',
  '12.2(44)SE3',
  '12.2(44)SE5',
  '12.2(44)SE6',
  '12.2(46)SE',
  '12.2(50)SE',
  '12.2(50)SE1',
  '12.2(50)SE3',
  '12.2(50)SE4',
  '12.2(50)SE5',
  '12.2(50)SQ',
  '12.2(50)SQ1',
  '12.2(50)SQ2',
  '12.2(50)SQ3',
  '12.2(50)SQ4',
  '12.2(50)SQ5',
  '12.2(50)SQ6',
  '12.2(50)SQ7',
  '12.2(52)SE',
  '12.2(54)SE',
  '12.2(55)SE',
  '12.2(55)SE10',
  '12.2(55)SE11',
  '12.2(55)SE3',
  '12.2(55)SE4',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(58)EX',
  '12.2(58)EZ',
  '12.2(58)SE2',
  '12.2(60)EZ4',
  '12.2(60)EZ5',
  '12.4(11)MR',
  '12.4(11)SW',
  '12.4(11)SW1',
  '12.4(11)SW2',
  '12.4(11)SW3',
  '12.4(11)T',
  '12.4(11)T1',
  '12.4(11)T2',
  '12.4(11)T3',
  '12.4(11)T4',
  '12.4(11)XJ',
  '12.4(11)XJ2',
  '12.4(11)XJ3',
  '12.4(11)XJ4',
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
  '12.4(12)MR',
  '12.4(12)MR1',
  '12.4(12)MR2',
  '12.4(14)XK',
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
  '12.4(15)XF',
  '12.4(15)XL',
  '12.4(15)XL1',
  '12.4(15)XL2',
  '12.4(15)XL3',
  '12.4(15)XL4',
  '12.4(15)XL5',
  '12.4(15)XM',
  '12.4(15)XM1',
  '12.4(15)XM2',
  '12.4(15)XM3',
  '12.4(15)XN',
  '12.4(15)XQ',
  '12.4(15)XQ1',
  '12.4(15)XQ2',
  '12.4(15)XQ2a',
  '12.4(15)XQ2b',
  '12.4(15)XQ3',
  '12.4(15)XQ4',
  '12.4(15)XQ5',
  '12.4(15)XQ6',
  '12.4(15)XQ7',
  '12.4(15)XQ8',
  '12.4(15)XR',
  '12.4(15)XR1',
  '12.4(15)XR10',
  '12.4(15)XR2',
  '12.4(15)XR3',
  '12.4(15)XR4',
  '12.4(15)XR5',
  '12.4(15)XR6',
  '12.4(15)XR7',
  '12.4(15)XR8',
  '12.4(15)XR9',
  '12.4(15)XY',
  '12.4(15)XY1',
  '12.4(15)XY2',
  '12.4(15)XY3',
  '12.4(15)XY4',
  '12.4(15)XY5',
  '12.4(15)XZ',
  '12.4(15)XZ1',
  '12.4(15)XZ2',
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
  '12.4(20)T',
  '12.4(20)T1',
  '12.4(20)T2',
  '12.4(20)T3',
  '12.4(20)T4',
  '12.4(20)T5',
  '12.4(20)T6',
  '12.4(20)YA',
  '12.4(20)YA1',
  '12.4(20)YA2',
  '12.4(20)YA3',
  '12.4(22)GC1',
  '12.4(22)T',
  '12.4(22)T1',
  '12.4(22)T2',
  '12.4(22)T3',
  '12.4(22)T4',
  '12.4(22)T5',
  '12.4(22)XR1',
  '12.4(22)XR10',
  '12.4(22)XR11',
  '12.4(22)XR12',
  '12.4(22)XR2',
  '12.4(22)XR3',
  '12.4(22)XR4',
  '12.4(22)XR5',
  '12.4(22)XR6',
  '12.4(22)XR7',
  '12.4(22)XR8',
  '12.4(22)XR9',
  '12.4(22)YB',
  '12.4(22)YB1',
  '12.4(22)YB2',
  '12.4(22)YB3',
  '12.4(22)YB4',
  '12.4(22)YB5',
  '12.4(22)YB6',
  '12.4(22)YB7',
  '12.4(22)YB8',
  '12.4(22)YD',
  '12.4(22)YD1',
  '12.4(22)YD2',
  '12.4(22)YD3',
  '12.4(22)YD4',
  '12.4(22)YE',
  '12.4(22)YE1',
  '12.4(22)YE2',
  '12.4(22)YE3',
  '12.4(22)YE4',
  '12.4(22)YE5',
  '12.4(22)YE6',
  '12.4(24)GC1',
  '12.4(24)GC3',
  '12.4(24)GC3a',
  '12.4(24)GC4',
  '12.4(24)GC5',
  '12.4(24)T',
  '12.4(24)T1',
  '12.4(24)T2',
  '12.4(24)T3',
  '12.4(24)T3e',
  '12.4(24)T3f',
  '12.4(24)T4',
  '12.4(24)T4a',
  '12.4(24)T4b',
  '12.4(24)T4c',
  '12.4(24)T4d',
  '12.4(24)T4e',
  '12.4(24)T4f',
  '12.4(24)T4l',
  '12.4(24)T5',
  '12.4(24)T6',
  '12.4(24)T7',
  '12.4(24)T8',
  '12.4(24)YE',
  '12.4(24)YE1',
  '12.4(24)YE2',
  '12.4(24)YE3',
  '12.4(24)YE3a',
  '12.4(24)YE3b',
  '12.4(24)YE3c',
  '12.4(24)YE3d',
  '12.4(24)YE3e',
  '12.4(24)YE4',
  '12.4(24)YE5',
  '12.4(24)YE6',
  '12.4(24)YE7',
  '12.4(24)YG1',
  '12.4(24)YG2',
  '12.4(24)YG3',
  '12.4(24)YG4',
  '15.0(1)EX',
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
  '15.0(1)MR',
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
  '15.0(2)MR',
  '15.0(2)SQD',
  '15.0(2)SQD1',
  '15.0(2)SQD2',
  '15.0(2)SQD3',
  '15.0(2)SQD4',
  '15.1(1)MR',
  '15.1(1)MR1',
  '15.1(1)MR2',
  '15.1(1)MR3',
  '15.1(1)MR4',
  '15.1(1)S',
  '15.1(1)S1',
  '15.1(1)S2',
  '15.1(1)T',
  '15.1(1)T1',
  '15.1(1)T2',
  '15.1(1)T3',
  '15.1(1)T4',
  '15.1(1)T5',
  '15.1(1)XB',
  '15.1(2)EY',
  '15.1(2)EY1a',
  '15.1(2)EY2',
  '15.1(2)EY2a',
  '15.1(2)EY3',
  '15.1(2)EY4',
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.1(2)GC2',
  '15.1(2)S',
  '15.1(2)S1',
  '15.1(2)S2',
  '15.1(2)SNG',
  '15.1(2)SNH',
  '15.1(2)SNI',
  '15.1(2)SNI1',
  '15.1(2)SY',
  '15.1(2)T',
  '15.1(2)T0a',
  '15.1(2)T1',
  '15.1(2)T2',
  '15.1(2)T2a',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(2)T5',
  '15.1(3)MR',
  '15.1(3)MRA',
  '15.1(3)MRA1',
  '15.1(3)MRA2',
  '15.1(3)S',
  '15.1(3)S0a',
  '15.1(3)S1',
  '15.1(3)S2',
  '15.1(3)S3',
  '15.1(3)S4',
  '15.1(3)S5',
  '15.1(3)S5a',
  '15.1(3)S6',
  '15.1(3)T',
  '15.1(3)T1',
  '15.1(3)T2',
  '15.1(3)T3',
  '15.1(3)T4',
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
  '15.2(1)GC',
  '15.2(1)GC1',
  '15.2(1)GC2',
  '15.2(1)S',
  '15.2(1)S1',
  '15.2(1)S2',
  '15.2(1)T',
  '15.2(1)T1',
  '15.2(1)T2',
  '15.2(1)T3',
  '15.2(1)T3a',
  '15.2(1)T4',
  '15.2(2)GC',
  '15.2(2)JB',
  '15.2(2)JB2',
  '15.2(2)JB3',
  '15.2(2)JB4',
  '15.2(2)JB5',
  '15.2(2)JB6',
  '15.2(2)S',
  '15.2(2)S0a',
  '15.2(2)S0c',
  '15.2(2)S1',
  '15.2(2)S2',
  '15.2(2)SNG',
  '15.2(2)SNH1',
  '15.2(2)SNI',
  '15.2(2)T',
  '15.2(2)T1',
  '15.2(2)T2',
  '15.2(2)T3',
  '15.2(2)T4',
  '15.2(3)GC',
  '15.2(3)GC1',
  '15.2(3)T',
  '15.2(3)T1',
  '15.2(3)T2',
  '15.2(3)T3',
  '15.2(3)T4',
  '15.2(4)GC',
  '15.2(4)GC1',
  '15.2(4)GC2',
  '15.2(4)GC3',
  '15.2(4)JA',
  '15.2(4)JA1',
  '15.2(4)JB',
  '15.2(4)JB1',
  '15.2(4)JB2',
  '15.2(4)JB3',
  '15.2(4)JB3a',
  '15.2(4)JB3b',
  '15.2(4)JB3h',
  '15.2(4)JB3s',
  '15.2(4)JB4',
  '15.2(4)JB5',
  '15.2(4)JB50',
  '15.2(4)JB5h',
  '15.2(4)JB5m',
  '15.2(4)JB6',
  '15.2(4)JB7',
  '15.2(4)JN',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M10',
  '15.2(4)M11',
  '15.2(4)M2',
  '15.2(4)M3',
  '15.2(4)M4',
  '15.2(4)M5',
  '15.2(4)M6',
  '15.2(4)M6a',
  '15.2(4)M7',
  '15.2(4)M8',
  '15.2(4)M9',
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
  '15.3(1)S',
  '15.3(1)S1',
  '15.3(1)S2',
  '15.3(1)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)S',
  '15.3(2)S1',
  '15.3(2)S2',
  '15.3(2)T',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.3(3)JA',
  '15.3(3)JA1',
  '15.3(3)JA10',
  '15.3(3)JA1m',
  '15.3(3)JA1n',
  '15.3(3)JA4',
  '15.3(3)JA5',
  '15.3(3)JA6',
  '15.3(3)JA7',
  '15.3(3)JA77',
  '15.3(3)JA8',
  '15.3(3)JA9',
  '15.3(3)JAA',
  '15.3(3)JAB',
  '15.3(3)JAX',
  '15.3(3)JAX1',
  '15.3(3)JAX2',
  '15.3(3)JB',
  '15.3(3)JB75',
  '15.3(3)JBB',
  '15.3(3)JBB1',
  '15.3(3)JBB2',
  '15.3(3)JBB4',
  '15.3(3)JBB5',
  '15.3(3)JBB50',
  '15.3(3)JBB6',
  '15.3(3)JBB6a',
  '15.3(3)JBB8',
  '15.3(3)JC',
  '15.3(3)JC1',
  '15.3(3)JC2',
  '15.3(3)JC3',
  '15.3(3)JC4',
  '15.3(3)JD',
  '15.3(3)JD2',
  '15.3(3)JN3',
  '15.3(3)JN4',
  '15.3(3)JN7',
  '15.3(3)JN8',
  '15.3(3)JNB',
  '15.3(3)JNB1',
  '15.3(3)JNB2',
  '15.3(3)JNB3',
  '15.3(3)JNC',
  '15.3(3)JNC1',
  '15.3(3)JNP',
  '15.3(3)JNP1',
  '15.3(3)JNP2',
  '15.3(3)JPB',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.3(3)M3',
  '15.3(3)M4',
  '15.3(3)M5',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(3)M8',
  '15.3(3)M8a',
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S1a',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S6',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S8a',
  '15.4(1)CG',
  '15.4(1)CG1',
  '15.4(1)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(1)S3',
  '15.4(1)S4',
  '15.4(1)T',
  '15.4(1)T1',
  '15.4(1)T2',
  '15.4(1)T3',
  '15.4(1)T4',
  '15.4(2)CG',
  '15.4(2)S1',
  '15.4(2)S2',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(2)T',
  '15.4(2)T1',
  '15.4(2)T2',
  '15.4(2)T3',
  '15.4(2)T4',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M6a',
  '15.4(3)S',
  '15.4(3)S1',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.5(1)S',
  '15.5(1)S1',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(1)S4',
  '15.5(1)T',
  '15.5(1)T1',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(1)T4',
  '15.5(2)S',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)S3',
  '15.5(2)S4',
  '15.5(2)T',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(3)M',
  '15.5(3)M0a',
  '15.5(3)M1',
  '15.5(3)M2',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)S',
  '15.5(3)S0a',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(1)S1',
  '15.6(1)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(1)T2',
  '15.6(2)S',
  '15.6(2)T' );

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

