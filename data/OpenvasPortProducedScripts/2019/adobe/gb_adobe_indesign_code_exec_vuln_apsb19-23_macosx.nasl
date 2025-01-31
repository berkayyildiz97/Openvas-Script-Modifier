# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814966");
  script_version("2019-10-23T10:55:06+0000");
  script_cve_id("CVE-2019-7107");
  script_bugtraq_id(107821);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-23 10:55:06 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 14:57:12 +0530 (Thu, 11 Apr 2019)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("Adobe InDesign Arbitrary Code Execution Vulnerability-APSB19-23 (Mac OS X)");

  script_tag(name:"summary", value:"This host is running Adobe InDesign and is
  prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists de to unsafe hyperlink processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application. Failed
  attacks may cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Adobe InDesign versions 14.0.1 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 14.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb19-23.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_indesign_server_detect_macosx.nasl");
  script_mandatory_keys("InDesign/Server/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

vers = infos['version'];
path = infos['location'];
if(version_is_less(version:vers, test_version:"14.0.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.0.2", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
