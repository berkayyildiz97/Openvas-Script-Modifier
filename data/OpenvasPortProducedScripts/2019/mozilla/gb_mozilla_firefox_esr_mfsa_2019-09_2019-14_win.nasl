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


CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814897");
  script_version("2019-08-01T07:22:04+0000");
  script_cve_id("CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818",
                "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-11691", "CVE-2019-11692",
                "CVE-2019-7317", "CVE-2019-11693", "CVE-2018-18511", "CVE-2019-9797",
                "CVE-2019-11694", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-9800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-01 07:22:04 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-05-22 12:29:43 +0530 (Wed, 22 May 2019)");
  script_name("Mozilla Firefox ESR Security Updates (mfsa_2019-09_2019-14)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A type confusion error with object groups and UnboxedObjects.

  - A cross-domain theft of images using canvas.

  - Multiple use-after-free errors in crash generation server, ChromeEventHandler,
    XMLHttpRequest, libpng library.

  - A buffer overflow error in WebGL bufferdata.

  - Cross-origin theft of images with createImageBitmap, ImageBitmapRenderingContext.

  - An out-of-bounds read error in Skia.

  - Memory Safety bugs.

  - JavaScript compartment mismatch with fetch API.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to bypass security restrictions, read sensitive data
  and browser history, crash the application and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 60.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 60.7
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-14/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"60.7"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"60.7", install_path:ffPath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
