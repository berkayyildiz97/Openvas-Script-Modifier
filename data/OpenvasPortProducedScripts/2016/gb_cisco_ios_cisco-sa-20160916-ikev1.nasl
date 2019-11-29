###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS Software IKEv1 Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106259");
  script_cve_id("CVE-2016-6415");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco IOS Software IKEv1 Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb29204");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb36055");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the referenced vendor advisory for more information on the fixed versions.");

  script_tag(name:"summary", value:"A vulnerability in IKEv1 packet processing code in Cisco IOS Software
could allow an unauthenticated, remote attacker to retrieve memory contents, which could lead to the
disclosure of confidential information.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient condition checks in the part of
the code that handles IKEv1 security negotiation requests. An attacker could exploit this vulnerability by
sending a crafted IKEv1 packet to an affected device configured to accept IKEv1 security negotiation requests.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to retrieve memory contents,
which could lead to the disclosure of confidential information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-09-19 09:23:33 +0700 (Mon, 19 Sep 2016)");
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
  '12.2(18)IXA',
  '12.2(18)IXB',
  '12.2(18)IXB1',
  '12.2(18)IXB2',
  '12.2(18)IXC',
  '12.2(18)IXD',
  '12.2(18)IXD1',
  '12.2(18)IXE',
  '12.2(18)IXF',
  '12.2(18)IXF1',
  '12.2(18)IXG',
  '12.2(18)IXH',
  '12.2(18)IXH1',
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
  '12.2(33)SB2',
  '12.2(33)SB3',
  '12.2(33)SB4',
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
  '12.2(33)SCJ1',
  '12.2(33)SCJ1a',
  '12.2(33)SCJ1b',
  '12.2(33)SCJ2',
  '12.2(33)SCJ2a',
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
  '12.2(52)SE',
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
  '12.2(33)SRA',
  '12.2(33)SRA1',
  '12.2(33)SRA2',
  '12.2(33)SRA3',
  '12.2(33)SRA4',
  '12.2(33)SRA5',
  '12.2(33)SRA6',
  '12.2(33)SRA7',
  '12.2(33)SRB',
  '12.2(33)SRB1',
  '12.2(33)SRB2',
  '12.2(33)SRB3',
  '12.2(33)SRB4',
  '12.2(33)SRB5',
  '12.2(33)SRB5a',
  '12.2(33)SRB6',
  '12.2(33)SRB7',
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
  '12.2(99)SX1003',
  '12.2(99)SX1006',
  '12.2(99)SX1010',
  '12.2(99)SX1012',
  '12.2(99)SX1017',
  '12.2(18)SXD',
  '12.2(18)SXD1',
  '12.2(18)SXD2',
  '12.2(18)SXD3',
  '12.2(18)SXD4',
  '12.2(18)SXD5',
  '12.2(18)SXD6',
  '12.2(18)SXD7',
  '12.2(18)SXD7a',
  '12.2(18)SXD7b',
  '12.2(18)SXE',
  '12.2(18)SXE1',
  '12.2(18)SXE2',
  '12.2(18)SXE3',
  '12.2(18)SXE4',
  '12.2(18)SXE5',
  '12.2(18)SXE6',
  '12.2(18)SXE6a',
  '12.2(18)SXE6b',
  '12.2(18)SXF',
  '12.2(18)SXF1',
  '12.2(18)SXF10',
  '12.2(18)SXF10a',
  '12.2(18)SXF11',
  '12.2(18)SXF12',
  '12.2(18)SXF12a',
  '12.2(18)SXF13',
  '12.2(18)SXF14',
  '12.2(18)SXF15',
  '12.2(18)SXF15a',
  '12.2(18)SXF16',
  '12.2(18)SXF17',
  '12.2(18)SXF17a',
  '12.2(18)SXF17b',
  '12.2(18)SXF2',
  '12.2(18)SXF3',
  '12.2(18)SXF4',
  '12.2(18)SXF5',
  '12.2(18)SXF6',
  '12.2(18)SXF7',
  '12.2(18)SXF8',
  '12.2(18)SXF9',
  '12.2(33)SXH',
  '12.2(33)SXH1',
  '12.2(33)SXH2',
  '12.2(33)SXH2a',
  '12.2(33)SXH3',
  '12.2(33)SXH3a',
  '12.2(33)SXH4',
  '12.2(33)SXH5',
  '12.2(33)SXH6',
  '12.2(33)SXI',
  '12.2(33)SXI1',
  '12.2(33)SXI2',
  '12.2(33)SXI2a',
  '12.2(33)SXI3',
  '12.2(50)SY',
  '12.2(50)SY1',
  '12.2(50)SY2',
  '12.2(50)SY3',
  '12.2(50)SY4',
  '12.2(33)XN1',
  '12.2(18)ZU',
  '12.2(18)ZU1',
  '12.2(18)ZU2',
  '12.2(18)ZY',
  '12.2(18)ZY1',
  '12.2(18)ZY2',
  '12.2(18)ZYA',
  '12.2(18)ZYA1',
  '12.2(18)ZYA2',
  '12.2(18)ZYA3',
  '12.2(18)ZYA3a',
  '12.2(18)ZYA3b',
  '12.2(18)ZYA3c',
  '12.3(8)JEC1',
  '12.3(8)JEC2',
  '12.3(8)JEC3',
  '12.3(8)JED',
  '12.3(4)T',
  '12.3(4)T1',
  '12.3(4)T10',
  '12.3(4)T11',
  '12.3(4)T2',
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
  '12.3(7)XI1b',
  '12.3(7)XI1c',
  '12.3(7)XI10',
  '12.3(7)XI10a',
  '12.3(7)XI2',
  '12.3(7)XI2a',
  '12.3(7)XI3',
  '12.3(7)XI4',
  '12.3(7)XI5',
  '12.3(7)XI6',
  '12.3(7)XI7',
  '12.3(7)XI7a',
  '12.3(7)XI7b',
  '12.3(7)XI8',
  '12.3(7)XI8a',
  '12.3(7)XI8c',
  '12.3(7)XI8d',
  '12.3(7)XI9',
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
  '12.4(15)MD',
  '12.4(15)MD1',
  '12.4(15)MD2',
  '12.4(15)MD3',
  '12.4(15)MD4',
  '12.4(15)MD5',
  '12.4(22)MD',
  '12.4(22)MD1',
  '12.4(22)MD2',
  '12.4(24)MD',
  '12.4(24)MD1',
  '12.4(24)MD2',
  '12.4(24)MD3',
  '12.4(24)MD4',
  '12.4(24)MD5',
  '12.4(24)MD6',
  '12.4(24)MD7',
  '12.4(22)MDA',
  '12.4(22)MDA1',
  '12.4(22)MDA2',
  '12.4(22)MDA3',
  '12.4(22)MDA4',
  '12.4(22)MDA5',
  '12.4(22)MDA6',
  '12.4(24)MDA1',
  '12.4(24)MDA10',
  '12.4(24)MDA11',
  '12.4(24)MDA12',
  '12.4(24)MDA13',
  '12.4(24)MDA2',
  '12.4(24)MDA3',
  '12.4(24)MDA4',
  '12.4(24)MDA5',
  '12.4(24)MDA6',
  '12.4(24)MDA7',
  '12.4(24)MDA8',
  '12.4(24)MDA9',
  '12.4(24)MDB',
  '12.4(24)MDB1',
  '12.4(24)MDB10',
  '12.4(24)MDB11',
  '12.4(24)MDB12',
  '12.4(24)MDB13',
  '12.4(24)MDB14',
  '12.4(24)MDB15',
  '12.4(24)MDB16',
  '12.4(24)MDB17',
  '12.4(24)MDB18',
  '12.4(24)MDB19',
  '12.4(24)MDB3',
  '12.4(24)MDB4',
  '12.4(24)MDB5',
  '12.4(24)MDB5a',
  '12.4(24)MDB6',
  '12.4(24)MDB7',
  '12.4(24)MDB8',
  '12.4(24)MDB9',
  '12.4(11)MR',
  '12.4(12)MR',
  '12.4(12)MR1',
  '12.4(12)MR2',
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
  '12.4(11)XJ',
  '12.4(11)XJ2',
  '12.4(11)XJ3',
  '12.4(11)XJ4',
  '12.4(14)XK',
  '12.4(6)XP',
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
  '15.0(2)ED',
  '15.0(2)ED1',
  '15.0(2)EH',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.0(2)EK',
  '15.0(2)EK1',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2a)EX5',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY3',
  '15.0(2)EZ',
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
  '15.0(2)MR',
  '15.0(1)S',
  '15.0(1)S1',
  '15.0(1)S2',
  '15.0(1)S3a',
  '15.0(1)S4',
  '15.0(1)S4a',
  '15.0(1)S5',
  '15.0(1)S6',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE10',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2a)SE9',
  '15.0(1)SY',
  '15.0(1)SY1',
  '15.0(1)SY10',
  '15.0(1)SY2',
  '15.0(1)SY3',
  '15.0(1)SY4',
  '15.0(1)SY5',
  '15.0(1)SY6',
  '15.0(1)SY7',
  '15.0(1)SY7a',
  '15.0(1)SY8',
  '15.0(1)SY9',
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
  '15.1(1)MR',
  '15.1(1)MR1',
  '15.1(1)MR2',
  '15.1(1)MR3',
  '15.1(1)MR4',
  '15.1(3)MR',
  '15.1(3)MRA',
  '15.1(3)MRA1',
  '15.1(3)MRA2',
  '15.1(3)MRA3',
  '15.1(3)MRA4',
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
  '15.1(3)S5a',
  '15.1(3)S6',
  '15.1(1)SG',
  '15.1(1)SG1',
  '15.1(1)SG2',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG7a',
  '15.1(2)SG8',
  '15.1(2)SNG',
  '15.1(2)SNH',
  '15.1(2)SNI',
  '15.1(2)SNI1',
  '15.1(1)SY',
  '15.1(1)SY1',
  '15.1(1)SY2',
  '15.1(1)SY3',
  '15.1(1)SY4',
  '15.1(1)SY5',
  '15.1(1)SY6',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY2',
  '15.1(2)SY3',
  '15.1(2)SY4',
  '15.1(2)SY4a',
  '15.1(2)SY5',
  '15.1(2)SY6',
  '15.1(2)SY7',
  '15.1(2)SY8',
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
  '15.2(1)E',
  '15.2(1)E1',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E6',
  '15.2(2a)E1',
  '15.2(3)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3a)E',
  '15.2(3a)E1',
  '15.2(3m)E2',
  '15.2(3m)E3',
  '15.2(3m)E6',
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(4)E3',
  '15.2(4m)E1',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5a)E',
  '15.2(5b)E',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(4)EC',
  '15.2(4)EC1',
  '15.2(3)EX',
  '15.2(1)EY',
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
  '15.2(2)SNG',
  '15.2(2)SNH1',
  '15.2(2)SNI',
  '15.2(1)SY',
  '15.2(1)SY0a',
  '15.2(1)SY1',
  '15.2(1)SY1a',
  '15.2(1)SY2',
  '15.2(1)SY3',
  '15.2(2)SY',
  '15.2(2)SY1',
  '15.2(2)SY2',
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
  '15.3(3)S1a',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S6',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(1)SY',
  '15.3(1)SY1',
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
  '15.4(3)M6',
  '15.4(3)S7',
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
  '15.4(3)S5a',
  '15.4(3)S6',
  '15.4(1)SY',
  '15.4(1)SY1',
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
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(1)S',
  '15.5(1)S1',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(1)S4',
  '15.5(2)S',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)S3',
  '15.5(2)S4',
  '15.5(3)S',
  '15.5(3)S0a',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S2a',
  '15.5(3)S2b',
  '15.5(3)S3',
  '15.5(3)SN',
  '15.5(1)T4',
  '15.5(1)T',
  '15.5(1)T1',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.6(3)M',
  '15.6(1)S',
  '15.6(1)S1',
  '15.6(1)S1a',
  '15.6(1)S2',
  '15.6(2)S',
  '15.6(2)S0a',
  '15.6(2)S1',
  '15.6(2)SN',
  '15.6(2)SP1',
  '15.6(2)SP',
  '15.6(1)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(1)T2',
  '15.6(2)T',
  '15.6(2)T1' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version: "See advisory" );
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );

