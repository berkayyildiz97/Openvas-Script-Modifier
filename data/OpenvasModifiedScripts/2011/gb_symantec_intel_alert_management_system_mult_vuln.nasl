###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_intel_alert_management_system_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Symantec Intel Alert Management System Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801835");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2010-0110", "CVE-2010-0111", "CVE-2011-0688");
  script_bugtraq_id(45935, 45936);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Symantec Intel Alert Management System Multiple Vulnerabilities");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/SAVCE/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
  or compromise a vulnerable system.");
  script_tag(name:"affected", value:"Symantec Antivirus Corporate Edition (SAVCE) 10.x before 10.1 MR10");
  script_tag(name:"insight", value:"Multiple flaws are caused by buffer overflow and input validation errors
  in the Intel Alert Management System (AMS2) when processing user-supplied
  packets, which could allow attackers or malicious users to trigger arbitrary
  events (launching a program, sending an email), shutdown the service, or
  execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to Symantec Antivirus Corporate Edition 10.1 MR10 or later.");
  script_tag(name:"summary", value:"This host is installed with Symantec AntiVirus Corporate Edition
  and is prone to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43099");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1024996");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0234");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110126_00");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.symantec.com/index.jsp");
  exit(0);
}


include("version_func.inc");

savceVer = get_kb_item("Symantec/SAVCE/Ver");
if(!savceVer){
  exit(0);
}

if(version_is_less_equal(version:savceVer,test_version:"10.1.8000.8")) {
  report = report_fixed_ver(installed_version:savceVer, vulnerable_range:"Less than or equal to 10.1.8000.8");
  security_message(port: 0, data: report);
}
