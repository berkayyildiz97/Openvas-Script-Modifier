###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2017-03_2017-03)-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809880");
  script_version("2019-06-25T08:25:15+0000");
  script_cve_id("CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380",
		"CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5383", "CVE-2017-5373");
  script_bugtraq_id(95757, 95758, 95769, 95762);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-06-25 08:25:15 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2017-01-27 12:20:32 +0530 (Fri, 27 Jan 2017)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2017-03_2017-03)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Excessive JIT code allocation allows bypass of ASLR and DEP.

  - Use-after-free in XSL.

  - Pointer and frame data leakage of Javascript objects.

  - Potential use-after-free during DOM manipulations.

  - Insecure communication methods in Developer Tools JSON viewer.

  - Use-after-free with Media Decoder.

  - Location bar spoofing with unicode characters.

  - Memory safety bugs fixed in Thunderbird 45.7.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  45.7 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 45.7.");


  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-03");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"45.7"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"45.7");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
