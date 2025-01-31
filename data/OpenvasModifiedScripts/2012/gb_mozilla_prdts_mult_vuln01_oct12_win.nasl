###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Vulnerabilities-01 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802994");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2012-4188", "CVE-2012-4187", "CVE-2012-4186", "CVE-2012-4185",
                "CVE-2012-4184", "CVE-2012-3982", "CVE-2012-3990", "CVE-2012-3988",
                "CVE-2012-3986", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-4183",
                "CVE-2012-4182", "CVE-2012-4181", "CVE-2012-4180", "CVE-2012-4179",
                "CVE-2012-3995", "CVE-2012-3994", "CVE-2012-3993", "CVE-2012-3983");
  script_bugtraq_id(55856);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-86.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-83.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-74.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-87.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-79.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-77.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-81.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-84.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-85.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-82.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-74.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-83.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross site scripting
  attacks, cause a denial of service memory corruption and application crash
  or possibly execute arbitrary code via unspecified vectors.");
  script_tag(name:"affected", value:"Mozilla Firefox versions before 16.0 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - memory corruption issues

  - An error within Chrome Object Wrapper (COW) when handling the
    'InstallTrigger' object can be exploited to access certain privileged
    functions and properties.

  - Use-after-free in the IME State Manager code.

  - combination of invoking full screen mode and navigating backwards in
    history could, in some circumstances, cause a hang or crash due to a
    timing dependent use-after-free pointer reference.

  - Several methods of a feature used for testing (DOMWindowUtils) are not
    protected by existing security checks, allowing these methods to be called
    through script by web pages.

  - An error when GetProperty function is invoked through JSAPI, security
    checking can be bypassed when getting cross-origin properties.

  - An issue with spoofing of the location property.

  - Use-after-free, buffer overflow, and out of bounds read issues.

  - The location property can be accessed by binary plugins through
    top.location and top can be shadowed by Object.define Property as well.
    This can allow for possible XSS attacks through plugins.

  - several memory safety bugs in the browser engine used in mozilla products.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 16.0 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"16.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"16.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}
