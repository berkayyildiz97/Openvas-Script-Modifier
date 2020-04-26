###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VM VirtualBox Unspecified Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902789");
  script_version("2019-12-18T15:04:04+0000");
  script_cve_id("CVE-2012-0111");
  script_bugtraq_id(51465);
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2012-01-24 11:43:28 +0530 (Tue, 24 Jan 2012)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability (MAC OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026531");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2012.html");

  script_tag(name:"impact", value:"Successful exploitation allows local users to affect confidentiality,
  integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle VM VirtualBox version 4.1");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors related to 'Shared Folders'
  sub component.");

  script_tag(name:"summary", value:"This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:oracle:vm_virtualbox";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version: version, test_version: "4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch", install_path: location );
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 4.1");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
