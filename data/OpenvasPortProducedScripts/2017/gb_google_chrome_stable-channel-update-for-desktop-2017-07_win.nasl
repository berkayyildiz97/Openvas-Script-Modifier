##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-07)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811539");
  script_version("2019-07-17T08:15:16+0000");
  script_cve_id("CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094",
                "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098",
                "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102",
                "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-7000", "CVE-2017-5105",
                "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109",
                "CVE-2017-5110");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-07-27 10:22:29 +0530 (Thu, 27 Jul 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-07)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to:

  - Use after free in IndexedDB.

  - Use after free in PPAPI.

  - UI spoofing in Blink.

  - Type confusion in extensions.

  - Out-of-bounds write in PDFium.

  - User information leak via Android intents.

  - Out-of-bounds read in Skia.

  - Use after free in V8.

  - Out-of-bounds write in PPAPI.

  - Use after free in Chrome Apps.

  - URL spoofing in OmniBox.

  - Uninitialized use in Skia.

  - UI spoofing in browser.

  - Pointer disclosure in SQLite.

  - User information leak via SVG.

  - Type confusion in PDFium.

  - UI spoofing in payments dialog.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct spoofing attacks,
  disclose sensitive information, cause a program to crash and can
  potentially result in the execution of arbitrary code or even enable
  full remote code execution capabilities.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 60.0.3112.78 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  60.0.3112.78 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/07/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"60.0.3112.78"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"60.0.3112.78");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
