###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox 'Password' Information Disclosure Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813894");
  script_version("2019-07-23T09:16:09+0000");
  script_cve_id("CVE-2018-12377", "CVE-2018-12378", "CVE-2018-18499", "CVE-2018-12379", "CVE-2018-12381",
                "CVE-2018-12383", "CVE-2018-12375", "CVE-2018-12376");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-23 09:16:09 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-09-06 13:22:59 +0530 (Thu, 06 Sep 2018)");
  script_name("Mozilla Firefox Security Updates (mfsa_2018-20) - Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An use-after-free error in refresh driver timers.

  - An use-after-free error in IndexedDB.

  - A same-origin policy violation using meta refresh and performance.getEntries to steal cross-origin URLs.

  - An out-of-bounds write error with malicious MAR file.

  - Page navigation error when the Outlook message's mail columns are incorrectly
    interpreted as a URL.

  - An error related to setting of a master password.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information, cause denial of service and run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version 58 through 61.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 62 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-20");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"58.0", test_version2:"61.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"62", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
