###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities - Sep15 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805756");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-7180", "CVE-2015-7179", "CVE-2015-7178", "CVE-2015-7177",
                "CVE-2015-7176", "CVE-2015-7175", "CVE-2015-7174", "CVE-2015-4522",
                "CVE-2015-4521", "CVE-2015-4520", "CVE-2015-4519", "CVE-2015-4517",
                "CVE-2015-4511", "CVE-2015-4509", "CVE-2015-4506", "CVE-2015-4505",
                "CVE-2015-4500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-09-29 18:11:28 +0530 (Tue, 29 Sep 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - Sep15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists due to,

  - Failed to  restrict the availability of High Resolution Time API times,

  - Multiple memory corruption flaws,

  - 'js/src/proxy/Proxy.cpp' mishandles certain receiver arguments,

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  and remote attackers to cause a denial of service or possibly execute arbitrary
  code, gain privileges and some unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 38.x before 38.3 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-114/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_in_range(version:ffVer, test_version:"38.0", test_version2:"38.2.1"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.3" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
