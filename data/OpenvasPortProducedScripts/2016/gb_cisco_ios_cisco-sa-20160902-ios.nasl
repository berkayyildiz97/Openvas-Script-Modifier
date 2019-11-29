###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS Software Point-to-Point Tunneling Protocol Server Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106222");
  script_cve_id("CVE-2016-6398");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco IOS Software Point-to-Point Tunneling Protocol Server Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160902-ios");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the implementation of Point-to-Point Tunneling
Protocol (PPTP) server functionality in Cisco IOS Software could allow an unauthenticated, remote attacker
to access data from a packet buffer that was previously used.

The vulnerability is due to the use of a previously used packet buffer whose content was not cleared
from memory. An attacker could exploit this vulnerability by sending a PPTP connection request to
device that is running a vulnerable release of the affected software and is configured for PPTP
server functionality. A successful exploit could allow the attacker to access up to 63 bytes of
memory that were previously used for a packet and were either destined to the device or generated by
the device. An exploit would not allow the attacker to access packet data from transit traffic. In
addition, an exploit would not allow the attacker to access arbitrary memory locations that the
attacker chooses.

Cisco has not released software updates that address this vulnerability. There is a workaround that
addresses this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-09-05 09:36:53 +0700 (Mon, 05 Sep 2016)");
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
  '15.5(3)M' );

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

