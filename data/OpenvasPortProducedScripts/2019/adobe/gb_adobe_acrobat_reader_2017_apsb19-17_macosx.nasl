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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814784");
  script_version("2019-07-16T10:51:36+0000");
  script_cve_id("CVE-2019-7061", "CVE-2019-7109", "CVE-2019-7110", "CVE-2019-7114",
                "CVE-2019-7115", "CVE-2019-7116", "CVE-2019-7121", "CVE-2019-7122",
                "CVE-2019-7123", "CVE-2019-7127", "CVE-2019-7111", "CVE-2019-7118",
                "CVE-2019-7119", "CVE-2019-7120", "CVE-2019-7124", "CVE-2019-7117",
                "CVE-2019-7128", "CVE-2019-7088", "CVE-2019-7112", "CVE-2019-7113",
                "CVE-2019-7125");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-16 10:51:36 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 11:01:09 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Acrobat Reader 2017 Security Updates (apsb19-17)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat Reader
  2017 and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Type confusionerrors.

  - Use After Free errors.

  - Heap Overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and run arbitrary code in context of
  current user.");

  script_tag(name:"affected", value:"Adobe Acrobat Reader 2017.011.30127 and earlier
  versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Reader 2017 version
  2017.011.30138 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

## 2017.011.30127 == 17.011.30127
if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30127")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30138 (2017.011.30138)", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
