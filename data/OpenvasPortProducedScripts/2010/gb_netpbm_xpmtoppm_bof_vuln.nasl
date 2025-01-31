###############################################################################
# OpenVAS Vulnerability Test
#
# NetPBM 'xpmtoppm' Converter Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800471");
  script_version("2019-12-18T15:04:04+0000");
  script_tag(name:"last_modification", value:"2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4274");
  script_bugtraq_id(38164);
  script_name("NetPBM 'xpmtoppm' Converter Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_netpbm_detect.nasl");
  script_family("Buffer overflow");
  script_mandatory_keys("NetPBM/Ver");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546580");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application or
  execute arbitrary code by tricking a user into converting a malicious image.");

  script_tag(name:"affected", value:"NetPBM versions prior to 10.47.07.");

  script_tag(name:"insight", value:"The flaw is due a buffer overflow error in the 'converter/ppm/xpmtoppm.c'
  converter when processing malformed header fields of 'X PixMap' (XPM) image files.");

  script_tag(name:"summary", value:"This host is installed with NetPBM and is prone to Buffer Overflow
  vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or update to NetPBM 10.47.07.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:netpbm:netpbm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

# NetPBM version 10.47.07(10.47.7)
if( version_is_less( version: version, test_version: "10.47.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.47.7", install_path: location );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
