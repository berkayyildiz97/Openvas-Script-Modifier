###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Updates( mfsa_2016-62_2016-84 )-Windows
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808640");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2016-5250", "CVE-2016-5268", "CVE-2016-5266", "CVE-2016-2835",
		"CVE-2016-5265", "CVE-2016-5264", "CVE-2016-5263", "CVE-2016-2837",
		"CVE-2016-5262", "CVE-2016-5261", "CVE-2016-5260", "CVE-2016-5259",
		"CVE-2016-5258", "CVE-2016-5255", "CVE-2016-5254", "CVE-2016-5253",
		"CVE-2016-0718", "CVE-2016-5252", "CVE-2016-5251", "CVE-2016-2838",
                "CVE-2016-2830", "CVE-2016-2836");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-08-08 14:53:06 +0530 (Mon, 08 Aug 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-62_2016-84 )-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer links mentioned in reference.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to spoof the address bar, to bypass the same origin
  policy, and conduct Universal XSS (UXSS) attacks, to read arbitrary files, to
  execute arbitrary code, to cause a denial of service, to discover cleartext
  passwords by reading a session restoration file and to obtain sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 48 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 48
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-84/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-83/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-82/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-81/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"48"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"48");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
