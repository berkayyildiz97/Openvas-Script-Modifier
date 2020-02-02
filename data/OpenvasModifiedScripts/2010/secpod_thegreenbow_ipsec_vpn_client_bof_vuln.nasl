###############################################################################
# OpenVAS Vulnerability Test
#
# TheGreenBow IPSec VPN Client Local Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902104");
  script_version("2019-12-18T15:04:04+0000");
  script_tag(name:"last_modification", value:"2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0392");
  script_name("TheGreenBow IPSec VPN Client Local Stack Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_thegreenbow_ipsec_vpn_client_detect.nasl");
  script_mandatory_keys("TheGreenBow-IPSec-VPN-Client/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55793");
  script_xref(name:"URL", value:"http://www.senseofsecurity.com.au/advisories/SOS-10-001");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary code on
  the system or compromise a system.");

  script_tag(name:"affected", value:"TheGreenBow IPSec VPN Client version 4.65.003 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing certain sections of
  'tgb' (policy) files. Passing an overly long string to 'OpenScriptAfterUp' will trigger the overflow.");

  script_tag(name:"summary", value:"This host has TheGreenBow IPSec VPN Client installed and is prone to Stack
  Overflow vulnerability.");

  script_tag(name:"solution", value:"Update to the most recent version.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:thegreenbow:thegreenbow_vpn_client";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.6.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Update to the most recent version.", install_path: location );
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to " + "4.6.5.3");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
