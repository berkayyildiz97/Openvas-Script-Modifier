###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Multiple Unspecified Vulnerabilities - Feb12 (MAC OS X 01)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802585");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2012-0443", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447");
  script_bugtraq_id(51756, 51765, 51752, 51757);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2012-02-06 14:03:00 +0530 (Mon, 06 Feb 2012)");
  script_name("Mozilla Products Multiple Unspecified Vulnerabilities - Feb12 (MAC OS X 01)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.7
  Thunderbird version 5.0 through 9.0
  Mozilla Firefox version 4.x through 9.0");
  script_tag(name:"insight", value:"The flaws are due to

  - Multiple unspecified vulnerabilities in browser engine

  - An error in frame scripts bypass XPConnect security checks when calling
    untrusted objects.

  - Not properly initializing data for image/vnd.microsoft.icon images, which
    allows remote attackers to obtain potentially sensitive information by
    reading a PNG image that was created through conversion from an ICO image.");

  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone

  to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 10.0 or later.

  Upgrade to SeaMonkey version to 2.7 or later.

  Upgrade to Thunderbird version to 10.0 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(!isnull(ffVer))
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"9.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"4.0 - 9.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.7"))
  {
    report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/MacOSX/Version");
if(!isnull(tbVer))
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"9.0")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"5.0 - 9.0");
    security_message(port: 0, data: report);
  }
}
