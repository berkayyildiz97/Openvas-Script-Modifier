###############################################################################
# OpenVAS Vulnerability Test
#
# AVG AntiVirus Version Detection (Mac OS X)
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

CPE = "cpe:/a:avg:anti-virus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811525");
  script_version("2019-12-16T09:24:51+0000");
  script_cve_id("CVE-2017-9977");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-12-16 09:24:51 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2017-07-17 14:59:13 +0530 (Mon, 17 Jul 2017)");
  script_name("AVG AntiVirus < 17.2 Security Bypass Vulnerability (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_avg_av_detect_macosx.nasl");
  script_mandatory_keys("avg/antivirus/detected");

  script_xref(name:"url", value:"https://wwws.nightwatchcybersecurity.com/2017/07/06/avg-antivirus-for-macos-doesnt-scan-inside-disk-images-cve-2017-9977/");

  script_tag(name:"summary", value:"The host is installed with AVG AntiVirus and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to AVG AntiVirus for MacOS does not scan files inside disk images (DMG) files
  in the on-demand scanner.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass malware detection by leveraging
  failure to scan inside disk image (aka DMG) files.");

  script_tag(name:"affected", value:"AVG AntiVirus version prior to 17.2 for MacOS.");

  script_tag(name:"solution", value:"Upgrade to AVG AntiVirus version 17.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable"); # Note: The issue was fixed in engine version 4668 in October 2016, and was confirmed again in version 17.2, virus database 170626-4. qod is reduced because nvt developed considering main antivirus version not the the scan engine version.

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"17.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.2", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
