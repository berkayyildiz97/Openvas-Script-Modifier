###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Browser Engine Multiple Unspecified Vulnerabilities March-11 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801905");
  script_version("2019-07-17T11:14:11+0000");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0062");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Browser Engine Multiple Unspecified Vulnerabilities March-11 (Windows)");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0531");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-09.html");

  script_xref(name:"URL", value:"http://www.mozillamessaging.com/en-US/thunderbird/");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors.");
  script_tag(name:"affected", value:"Thunderbird 3.1.x before 3.1.8
  Firefox version before 3.6.x before 3.6.14");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities are present in the browser engine,
  which allow remote attackers to cause a denial of service.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Thunderbird that are prone to
  multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.14 or later.
  Upgrade to Thunderbird version 3.1.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.13"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.6.0 - 3.6.13");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  if(version_in_range(version:tbVer, test_version:"3.1.0", test_version2:"3.1.7")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"3.1.0 - 3.1.7");
    security_message(port: 0, data: report);
  }
}
