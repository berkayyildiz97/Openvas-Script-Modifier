###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Enter Key Dialog Bypass and Use-After-Free Memory Corruption Vulnerabilities (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802185");
  script_version("2019-07-17T11:14:11+0000");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-3001", "CVE-2011-3005");
  script_bugtraq_id(49837, 49808);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Enter Key Dialog Bypass and Use-After-Free Memory Corruption Vulnerabilities (MAC OS X)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-40.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-44.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to, attackers to cause a denial
  of service (memory corruption and application crash) or possibly execute
  arbitrary code.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.4
  Thunderbird version prior to 7.0
  Mozilla Firefox version 4.x through 6");
  script_tag(name:"insight", value:"The flaws are due to

  - not preventing manual add-on installation in response to the holding of
    the Enter key.

  - a use-after-free error existing when parsing OGG headers.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to enter key dialog bypass and use-after-free memory corruption
  vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 7.0 or later, Upgrade to SeaMonkey version to 2.4 or later,
  Upgrade to Thunderbird version to 7.0 or later.");
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
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"6.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"6.1");
    security_message(data:report);
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.4"))
  {
    report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.4");
    security_message(data:report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/MacOSX/Version");
if(tbVer != NULL)
{
  if(version_is_less(version:tbVer, test_version:"7.0")){
    report = report_fixed_ver(installed_version:tbVer, fixed_version:"7.0");
    security_message(data:report);
  }
}
