# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:tigervnc:tigervnc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815880");
  script_version("2020-01-21T07:42:39+0000");
  script_tag(name:"last_modification", value:"2020-01-21 07:42:39 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-06 13:24:06 +0530 (Mon, 06 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694",
                "CVE-2019-15695");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TigerVNC Remote Code Execution Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tigervnc_detect_win.nasl");
  script_mandatory_keys("TigerVNC6432/Win/Installed");

  script_tag(name:"summary", value:"TigerVNC is prone to multiple remote code execution vulnerabilities.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An incorrect usage of stack memory in ZRLEDecoder

  - A heap buffer overflow error in TightDecoder::FilterGradient.

  - An insufficient sanitization of PixelFormat in CMsgReader::readSetCursor.

  - The signdness error in processing MemOutStream in DecodeManager::decodeRect.

  - An incorrect value checks in CopyRectDecoder.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"TigerVNC version prior to 1.10.1");

  script_tag(name:"solution", value:"Upgrade to TigerVNC version 1.10.1 or later.
  For updates refer the Reference Links.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/12/20/2");
  script_xref(name:"URL", value:"https://tigervnc.org/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos['version'];
path = infos['location'];
if(version_is_less(version: vers, test_version: "1.10.1"))
{
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.10.1", install_path: path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
