###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Information Disclosure Vulnerabilities - MAC OS X
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802546");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2010-5074", "CVE-2002-2437", "CVE-2002-2436");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2011-12-09 16:19:54 +0530 (Fri, 09 Dec 2011)");
  script_name("Mozilla Products Multiple Information Disclosure Vulnerabilities - MAC OS X");

  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-5074");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2002-2436");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2002-2437");
  script_xref(name:"URL", value:"http://vrda.jpcert.or.jp/feed/en/NISTNVD_CVE-2010-5074_AD_1.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to obtain sensitive information
  about visited web pages.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.1,
  Thunderbird version prior to 3.3 and
  Mozilla Firefox version prior to 4.0 on MAC OS");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in layout engine, executes different code for visited and
    unvisited links during the processing of CSS token sequences.

  - An error in JavaScript implementation, which does not properly restrict
    the set of values of objects returned by the getComputedStyle method.

  - An error in Cascading Style Sheets (CSS) implementation, which fails to
    handle the visited pseudo-class.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/seamonkey/thunderbird
  and is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 4.0 or later, Upgrade to SeaMonkey version to 2.1 or later,
  Upgrade to Thunderbird version 3.3 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozillamessaging.com/en-US/thunderbird/");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"4.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"4.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.1"))
  {
    report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/MacOSX/Version");
if(tbVer != NULL)
{
  if(version_is_less(version:tbVer, test_version:"3.3")){
    report = report_fixed_ver(installed_version:tbVer, fixed_version:"3.3");
    security_message(port: 0, data: report);
  }
}
