###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20160203-ucm.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Unified Communications Manager SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105543");
  script_cve_id("CVE-2016-1308");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 12096 $");

  script_name("Cisco Unified Communications Manager SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160203-ucm");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending crafted URLs that contain malicious SQL statements to the affected system. An exploit could allow the attacker to determine the presence of certain values in the database.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to a lack of input validation on user-supplied input in SQL queries.");
  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"A vulnerability in the Cisco Unified Communications Manager SQL database interface could allow an authenticated, remote attacker to impact the confidentiality of the system by executing arbitrary SQL queries.");
  script_tag(name:"affected", value:"Cisco Unified Communications Manager release 10.5(2.13900.9) is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-12 14:48:29 +0100 (Fri, 12 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

# example for detected version: 11.0.1.10000-10
vers = str_replace( string:vers, find:"-", replace:"." );

if( vers == '10.5.2.13900.9' )
{
  report = report_fixed_ver(  installed_version:vers, fixed_version:"See vendor advisory" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );

