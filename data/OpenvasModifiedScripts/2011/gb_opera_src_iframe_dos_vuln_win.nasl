###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_src_iframe_dos_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Opera Browser 'SRC' Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802113");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2641");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Opera Browser 'SRC' Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17396/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser Version 11.11");
  script_tag(name:"insight", value:"The flaw is due to setting the FACE attribute of a FONT element
within an IFRAME element after changing the SRC attribute of this IFRAME element
to an about:blank value.");
  script_tag(name:"solution", value:"Upgrade to Opera version 12.00.1467 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera browser and is prone to denial of
service Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/download/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  if(version_is_equal(version:operaVer, test_version:"11.11")){
    report = report_fixed_ver(installed_version:operaVer, vulnerable_range:"Equal to 11.11");
    security_message(port: 0, data: report);
  }
}
