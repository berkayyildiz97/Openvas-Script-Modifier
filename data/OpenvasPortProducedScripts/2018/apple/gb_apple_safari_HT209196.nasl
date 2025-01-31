###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Security Updates(HT209196)
#
# Authors:
# Vidta V Koushik <vidita@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814320");
  script_version("2019-07-05T08:56:43+0000");
  script_cve_id("CVE-2018-4374", "CVE-2018-4377", "CVE-2018-4372", "CVE-2018-4373",
                "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4382", "CVE-2018-4386",
                "CVE-2018-4392", "CVE-2018-4416", "CVE-2018-4409", "CVE-2018-4378");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-05 08:56:43 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-10-31 10:06:26 +0530 (Wed, 31 Oct 2018)");
  script_name("Apple Safari Security Updates(HT209196)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A logic issue due to improper validation.

  - A cross-site scripting issue due to improper URL validation.

  - A resource exhaustion issue due to improper input validation.

  - Multiple memory corruption issues due to poor memory handling and improper
    input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct universal cross site scripting, arbitrary code execution and
  cause a denial of service condition.");

  script_tag(name:"affected", value:"Apple Safari versions before 12.0.1");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 12.0.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209196");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
safVer = infos['version'];
safPath = infos['location'];

if(version_is_less(version:safVer, test_version:"12.0.1"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version: "12.0.1", install_path:safPath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
