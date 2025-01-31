##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2018-05)-Windows
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813354");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6120");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-11 11:12:21 +0530 (Fri, 11 May 2018)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2018-05)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Privilege Escalation in extensions.

  - Type confusion error in V8.

  - Heap buffer overflow error in PDFium.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, escalate privileges and also
  cause data corruption or unexpected behavior.");

  script_tag(name:"affected", value:"Google Chrome version prior to 66.0.3359.170 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  66.0.3359.170 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.google.co.in/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"66.0.3359.170"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"66.0.3359.170", install_path:chr_path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
