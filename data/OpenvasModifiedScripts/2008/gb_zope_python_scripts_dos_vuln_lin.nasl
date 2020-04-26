###############################################################################
# OpenVAS Vulnerability Test
#
# Zope Python Scripts Local Denial of Service Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800064");
  script_version("2020-02-03T13:52:45+0000");
  script_tag(name:"last_modification", value:"2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5102");
  script_bugtraq_id(32267);
  script_name("Zope Python Scripts Local Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.zope.org/advisories/advisory-2008-08-12");
  script_xref(name:"URL", value:"http://www.zope.org/Products/Zope/Hotfix-2008-08-12/README.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_zope_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated users to cause
  denial of service or resource exhaustion.");

  script_tag(name:"affected", value:"Zope Versions 2.x - 2.11.2 on Linux.");

  script_tag(name:"insight", value:"Zope server allows improper strings to be passed via certain raise and
  import commands.");

  script_tag(name:"summary", value:"This host is running Zope, and is prone to Denial of Service
  Vulnerability.");

  script_tag(name:"solution", value:"Update Zope to a later version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:zope:zope";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version:"2.0", test_version2:"2.11.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.11.3", install_path: location );
  report = report_fixed_ver(installed_version:version, vulnerable_range:"2.0 - 2.11.2");
  security_message(port: port, data: report);
  exit( 0 );
}

exit( 99 );
