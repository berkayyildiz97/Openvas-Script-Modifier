###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Updates(mfsa_2017-10_2017-12)-MAC OS X
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810752");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2017-5433", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5461",
"CVE-2017-5459", "CVE-2017-5466", "CVE-2017-5434", "CVE-2017-5432",
"CVE-2017-5460", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440",
"CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5464", "CVE-2017-5443",
"CVE-2017-5444", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5465",
"CVE-2017-5448", "CVE-2017-5437", "CVE-2016-1019", "CVE-2017-5454",
"CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5469", "CVE-2016-6354",
"CVE-2017-5445", "CVE-2017-5449", "CVE-2017-5450", "CVE-2017-5451",
"CVE-2017-5462", "CVE-2017-5463", "CVE-2017-5467", "CVE-2017-5452",
"CVE-2017-5453", "CVE-2017-5458", "CVE-2017-5468", "CVE-2017-5430",
"CVE-2017-5429");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-04-20 10:53:42 +0530 (Thu, 20 Apr 2017)");
  script_name("Mozilla Firefox Security Updates(mfsa_2017-10_2017-12)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - An use-after-free in SMIL animation functions,

  - An use-after-free during transaction processing in the editor,

  - An uut-of-bounds write with malicious font in Graphite 2,

  - An Out-of-bounds write in Base64 encoding in NSS,

  - The buffer overflow in WebGL,

  - The origin confusion when reloading isolated data:text/html URL,

  - An use-after-free during focus handling,

  - An use-after-free in text input selection,

  - An use-after-free in frame selection,

  - An use-after-free in nsAutoPtr during XSLT processing,

  - An use-after-free in nsTArray Length() during XSLT processing,

  - An use-after-free in txExecutionState destructor during XSLT processing,

  - An use-after-free with selection during scroll events,

  - An use-after-free during style changes,

  - The memory corruption with accessibility and DOM manipulation,

  - The out-of-bounds write during BinHex decoding,

  - The buffer overflow while parsing application/http-index-format content,

  - An out-of-bounds read when HTTP/2 DATA frames are sent with incorrect data,

  - An out-of-bounds read during glyph processing,

  - An out-of-bounds read in ConvolvePixel,

  - An out-of-bounds write in ClearKeyDecryptor,

  - The vulnerabilities in Libevent library,

  - The sandbox escape allowing file system read access through file picker,

  - The sandbox escape through internal feed reader APIs,

  - The sandbox escape allowing local file system access,

  - The Potential Buffer overflow in flex-generated code,

  - An uninitialized values used while parsing application/http-index-format content,

  - The crash during bidirectional unicode manipulation with animation,

  - An addressbar spoofing using javascript: URI on Firefox for Android,

  - An addressbar spoofing with onblur event,

  - The DRBG flaw in NSS,

  - The memory corruption when drawing Skia content,

  - The addressbar spoofing during scrolling with editable content on Firefox for Android,

  - The HTML injection into RSS Reader feed preview page through TITLE element,

  - The drag and drop of javascript: URLs can allow for self-XSS,

  - An incorrect ownership model for Private Browsing information and

  - The memory safety bugs fixed in Firefox 53 and Firefox ESR 52.1.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, to delete arbitrary files by leveraging
  certain local file execution, to obtain sensitive information, and to cause
  a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  53.0 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 53.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-10/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"53.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"53.0");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
