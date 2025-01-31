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


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815815");
  script_version("2019-12-05T07:54:08+0000");
  script_cve_id("CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702",
                "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706",
                "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710",
                "CVE-2019-13711", "CVE-2019-15903", "CVE-2019-13713", "CVE-2019-13714",
                "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718",
                "CVE-2019-13719");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-05 07:54:08 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-10-24 15:26:40 +0530 (Thu, 24 Oct 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_22-2019-10)-Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An use-after-free error in media.

  - A buffer overrun error in Blink.

  - Muultiple spoofing errors.

  - A privilege elevation error in Installer.

  - A CSP bypass error.

  - An extension permission bypass error.

  - An out-of-bounds read error in PDFium.

  - File storage disclosure.

  - HTTP authentication spoof.

  - File download protection bypass.

  - Cross-context information leak.

  - Cross-origin data leak.

  - CSS injection error.

  - Service worker state error.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to execute arbitrary code in the context of the browser, cause denial of
  service condition, disclose sensitive information and conduct spoofing attack..");

  script_tag(name:"affected", value:"Google Chrome version prior to 78.0.3904.70 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  78.0.3904.70 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/10/stable-channel-update-for-desktop_22.html");
  script_xref(name:"URL", value:"https://www.google.com/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"78.0.3904.70"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"78.0.3904.70", install_path:chr_path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
