###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802511");
  script_version("2019-09-16T06:54:58+0000");
  script_cve_id("CVE-2011-3651", "CVE-2011-3649");
  script_bugtraq_id(50597, 50591);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2011-11-11 15:10:19 +0530 (Fri, 11 Nov 2011)");
  script_name("Mozilla Products Multiple Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-48.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause denial of service and
  execute arbitrary code via unspecified vectors.");

  script_tag(name:"affected", value:"Thunderbird version 7.0

  Mozilla Firefox version 7.0.");

  script_tag(name:"insight", value:"The flaws are due to

  - unspecified errors in the browser engine.

  - Direct2D (aka D2D) API is used in conjunction with the Azure graphics
  back-end on windows.");

  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 8.0 or later, Upgrade to Thunderbird version to 8.0 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_equal(version:ffVer, test_version:"7.0"))
  {
     report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"Equal to 7.0");
     security_message(port: 0, data: report);
     exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  if(version_is_equal(version:tbVer, test_version:"7.0")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"Equal to 7.0");
    security_message(port: 0, data: report);
  }
}
