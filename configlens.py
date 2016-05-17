import re
import os
import sys
import copy
import logging
import untangle
import collections
import subprocess as sp
logging.basicConfig(filename='cl.log',
                    filemode='w',
                    level=logging.INFO,
                    format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')

logging.info("Started Program")

def disply(ds1, ds2):
    fmtstr = ''
    if 'op_values' in ds1:
        # just ensure ds1 and ds2 have equal number of strings to display
        # just for the sake of formatting display
        if len(ds1['op_values']) > len(ds2):
            temp = len(ds1['op_values']) - len(ds2)
            for i in xrange(0, temp - 1):
                ds2.append('')
        if len(ds1['op_values']) < len(ds2):
            temp = len(ds2) - len(ds1['op_values'])
            for i in xrange(0, temp - 1):
                ds1['op_values'].append('')
        if len(ds1['op_values']) > 1:
            count = 0
            for i, j in zip(ds1['op_values'], ds2):
                if count == 0:
                    fmtstr += "{0:<45}{1:<45}\n".format(i, j)
                    count += 1
                else:
                    fmtstr += "{0:>25}{1:<45}{2:<45}\n".format('', i, j)
                    count += 1
            return fmtstr.strip()
        else:
            return "{0:<45}{1:<45}".format(ds1['op_values'],ds2)
    else:
        return ''
    
class PAN_Parse:

    obj = None
    filepath = None
    sec_rules = None
    nat_rules = None
    nat_rules_list = []
    sec_rules_list = []
    allow_rules_list = []
    deny_rules_list = []
    # nat datastructure
    nat_ds = {}
    nat_ds['dest'] = []    
    nat_ds['source'] = []
    nat_ds['to'] = []
    nat_ds['from'] = []
    nat_ds['service'] = []
    nat_ds['rule_num'] = None    
    nat_ds['translation_type'] = None
    nat_ds['translation_address'] = None
    # security datastructure
    sec_ds = {}
    sec_ds['rule_num'] = None
    sec_ds['services'] = []    
    sec_ds['dest_zone'] = []
    sec_ds['application'] = []    
    sec_ds['source_zone'] = []
    sec_ds['dest_address'] = []
    sec_ds['source_address'] = []
    sec_ds['user_access_enabled'] = []
    sec_ds['action'] = None

    def __init__(self, filepath):
        self.filepath = filepath
        self.obj = untangle.parse(filepath)
        self.sec_rules_list = self.process_all_sec_rules()
        self.nat_rules_list = self.process_all_nat_rules()
        
    def get_sec_allow_rule_count(self):
        return len(self.allow_rules_list)

    def get_sec_deny_rule_count(self):
        return len(self.deny_rules_list)

    def get_all_sec_rules(self):
        return self.sec_rules_list
    
    def get_all_nat_rules(self):
        return self.nat_rules_list

    def get_sec_rule_count(self):
        sec_rules = None
        try:
            rulestr = str(self.obj.config.devices.entry.vsys.entry.rulebase.security.rules.entry[-1]['name'])
            mobj = re.match(r'Rule\s*(\d+)?', rulestr)
            logging.info("PAN: Total # security rules are : " + mobj.group(1))
            self.sec_rules = int(mobj.group(1))
            # TODO process each security rule
        except TypeError, e:
            if self.obj.config.devices.entry.vsys.entry.rulebase.security.rules.entry['name'] != '':
                logging.info("PAN: Total # security rules are : 1")
                self.sec_rules = 1
            else:
                logging.info("PAN: There are no security rules!!")
        return self.sec_rules

    def get_nat_rule_count(self):
        self.nat_rules = None 
        try:
            rulestr = str(self.obj.config.devices.entry.vsys.entry.rulebase.nat.rules.entry[-1]['name'])
            mobj = re.match(r'Rule\s*(\d+)?', rulestr)
            logging.info("PAN: Total # nat rules are : " + mobj.group(1))
            self.nat_rules = int(mobj.group(1))
        except TypeError, e:
            if self.obj.config.devices.entry.vsys.entry.rulebase.nat.rules.entry['name'] != '':
                logging.info("PAN: Total # nat rules are : 1")
                self.nat_rules = 1
            else:
                logging.info("PAN: There are no nat rules!!")
        return self.nat_rules

    def process_all_sec_rules(self):
        """ In this we get the
        1) rule #
        2) source zone -- from in PAN
        3) destination zone -- to in PAN
        4) source address -- source in PAN
        5) destination address -- destination in PAN
        6) user access enabled -- source-user in PAN
        7) application 
        8) services
        9) policy action -- action in PAN
        """
        # check how many sec rules are there
        if self.sec_rules is None:
            self.get_sec_rule_count()        
            if self.sec_rules is None:
                logging.error("There are NO security rules in the PAN cfg file!!")
                return
        sec_root_obj = self.obj.config.devices.entry.vsys.entry.rulebase.security.rules
        if self.sec_rules == 1:
            # read each nat rule one by one
            secds = copy.deepcopy(self.sec_ds)
            secds['rule_num'] = str(sec_root_obj.entry['name'])
            
            # we can't use 'from' in the tag name
            for tag in sec_root_obj.entry[i].children:
                if re.search(r'<from>', str(tag)):
                    if isinstance(tag.member, list):
                        for k in tag.member:
                            secds['source_zone'].append(str(k.cdata))
                    else:
                        secds['source_zone'].append(str(tag.member.cdata))                            
                    break
            for k in sec_root_obj.entry.to.member:
                secds['dest_zone'].append(str(k.cdata))
            for k in sec_root_obj.entry.source.member:
                secds['source_address'].append(str(k.cdata))
            for k in sec_root_obj.entry.destination.member:
                secds['dest_address'].append(str(k.cdata))
            for k in sec_root_obj.entry.source_user.member:
                secds['user_access_enabled'].append(str(k.cdata))
            for k in sec_root_obj.entry.application.member:
                secds['application'].append(str(k.cdata))
            for k in sec_root_obj.entry.service.member:
                secds['services'].append(str(k.cdata))
            secds['action'] = str(sec_root_obj.entry.action.cdata)
            if secds['action'] == 'allow':
                self.allow_rules_list.append(secds)
            elif secds['action'] == 'deny':
                self.deny_rules_list.append(secds)
            self.sec_rules_list.append(secds)
        
        elif self.sec_rules > 1:
            for i in xrange(self.sec_rules):
                # read each sec rule one by one
                secds = copy.deepcopy(self.sec_ds)
                logging.info("PAN rule " + str(sec_root_obj.entry[i]['name']))
                secds['rule_num'] = str(sec_root_obj.entry[i]['name'])
                # we can't use 'from' in the tag name
                for tag in sec_root_obj.entry[i].children:
                    if re.search(r'<from>', str(tag)):
                        if isinstance(tag.member, list):
                            for k in tag.member:
                                secds['source_zone'].append(str(k.cdata))
                        else:
                            secds['source_zone'].append(str(tag.member.cdata))                            
                        break
                for k in sec_root_obj.entry[i].to.member:
                    secds['dest_zone'].append(str(k.cdata))
                for k in sec_root_obj.entry[i].source.member:
                    secds['source_address'].append(str(k.cdata))
                for k in sec_root_obj.entry[i].destination.member:
                    secds['dest_address'].append(str(k.cdata))
                for k in sec_root_obj.entry[i].source_user.member:
                    secds['user_access_enabled'].append(str(k.cdata))
                for k in sec_root_obj.entry[i].application.member:
                    secds['application'].append(str(k.cdata))
                for k in sec_root_obj.entry[i].service.member:
                    secds['services'].append(str(k.cdata))
                secds['action'] = str(sec_root_obj.entry[i].action.cdata)
                if secds['action'] == 'allow':
                    self.allow_rules_list.append(secds)
                elif secds['action'] == 'deny':
                    self.deny_rules_list.append(secds)
                self.sec_rules_list.append(secds)
        return self.sec_rules_list

    
    def process_all_nat_rules(self):
        """ In this we get the 
        1) source members,
        2) destination members,
        3) service members,
        4) translation_type,
        5) translation address,
              and 
        6) rule # """
        
        # check how many nat rules are there
        if self.nat_rules is None:
            self.get_nat_rule_count()        
            if self.nat_rules is None:
                logging.error("There are NO NAT rules in the PAN cfg file!!")
                return
        nat_root_obj = self.obj.config.devices.entry.vsys.entry.rulebase.nat.rules            
        if self.nat_rules == 1:
            # read each nat rule one by one
            natds = copy.deepcopy(self.nat_ds)
            # get the source members
            for k in nat_root_obj.entry.source.member:
                natds['source'].append(str(k.cdata))
            for k in nat_root_obj.entry.to.member:
                natds['to'].append(str(k.cdata))
            # we can't use 'from' in the tag name
            for tag in nat_root_obj.entry.children:
                if re.search(r'<from>', str(tag)):
                    if isinstance(tag.member, list):
                        for k in tag.member:
                            natds['from'].append(str(k.cdata))
                    else:
                        natds['from'].append(str(tag.member.cdata))                            
                        break
                
            # get the destination members
            for k in nat_root_obj.entry.destination.member:
                natds['dest'].append(str(k.cdata))
            # get the service members
            for k in nat_root_obj.entry.service.member:
                natds['service'].append(str(k.cdata))
            # get the translation type
            mobj = re.match(r'Element\s*<(.*)?>\s*with', str(nat_root_obj.entry.children[0]))
            natds['translation_type'] = mobj.group(1)
            # get the translated address
            natds['translation_address'] = str(nat_root_obj.entry.children[0].children[0].translated_address.member.cdata)
            # get the rule name
            natds['rule_num'] = nat_root_obj.entry['name']
            self.nat_rules_list.append(natds)
        elif self.nat_rules > 1:
            for i in xrange(self.nat_rules):
                # read each nat rule one by one
                natds = copy.deepcopy(self.nat_ds)
            for k in nat_root_obj.entry[i].to.member:
                natds['to'].append(str(k.cdata))
            # we can't use 'from' in the tag name
            for tag in nat_root_obj.entry[i].children:
                if re.search(r'<from>', str(tag)):
                    if isinstance(tag.member, list):
                        for k in tag.member:
                            natds['from'].append(str(k.cdata))
                    else:
                        natds['from'].append(str(tag.member.cdata))                            
                        break
                
                # get the source members
                for k in nat_root_obj.entry[i].source.member:
                    natds['source'].append(str(k.cdata))
                    
                # get the destination members
                for k in nat_root_obj.entry[i].destination.member:
                    natds['dest'].append(str(k.cdata))
                # get the service members
                for k in nat_root_obj.entry[i].service.member:
                    natds['service'].append(str(k.cdata))
                # get the translation type
                mobj = re.match(r'Element\s*<(.*)?>\s*with', str(nat_root_obj.entry[i].children[0]))
                natds['translation_type'] = mobj.group(1)
                # get the translated address
                natds['translation_address'] = str(nat_root_obj.entry[i].children[0].children[0].translated_address.member.cdata)
                # get the rule name
                natds['rule_num'] = nat_root_obj.entry[i]['name']
                self.nat_rules_list.append(natds)
        return self.nat_rules_list

    
class CHKP_Parse():

    # chkp rule counter
    crc = 0
    # chkp rule adtr counter
    crac = 0
    filepath = None
    sec_rules = None
    nat_rules = None
    allow_rules = []
    deny_rules = []
    
    # chkp class names
    ccn = {}
    RULE_VPN = 13
    RULE_SOURCE = 12
    DROP_ACTION = 14
    RULE_INSTALL = 10
    SECURITY_RULE = 6
    ACCEPT_ACTION = 7
    RULE_SERVICES = 11
    TRANSLATE_HIDE = 5
    FIREWALL_POLICY = 1
    RULE_USER_GROUP = 15
    TRANSLATE_STATIC = 3
    RULE_DESTINATION = 9
    SERVICE_TRANSLATE = 4
    IDENTITY_ACTION_SETTINGS = 8
    ADDRESS_TRANSLATION_RULE = 2
    
    ccn = {
        'rule_vpn': RULE_VPN,
        'drop_action': DROP_ACTION,                               
        'rule_source': RULE_SOURCE,
        'rule_install': RULE_INSTALL,
        'security_rule': SECURITY_RULE,
        'accept_action': ACCEPT_ACTION,
        'rule_services': RULE_SERVICES,
        'translate_hide': TRANSLATE_HIDE,
        'rule_user_group': RULE_USER_GROUP,
        'firewall_policy': FIREWALL_POLICY,            
        'translate_static': TRANSLATE_STATIC,
        'rule_destination': RULE_DESTINATION,
        'service_translate': SERVICE_TRANSLATE,                               
        'identity_action_settings': IDENTITY_ACTION_SETTINGS,
        'address_translation_rule': ADDRESS_TRANSLATION_RULE
    }
    # contains entire chkp cfg data
    glbl = {}
    uid = None
    # each open bracket has to match with a closed bracket some where
    # so by the end of parsing the config file, parenest
    # should be zero again. When we come across an open bracket we
    # increment this by one and when we come across a closed bracket
    # we decrement it by one
    
    parenest = 0
    
    lasttag = None
    # the following are markers to correctly process the cfg data
    # this is userdefined convinience flag to get values for op/compound tags    
    isgate = False 
    istime = False
    istrack = False
    isparse = False
    isaction = False
    isaccept = False
    isoptions = False
    isdstadtr = False
    isclauthtrack = False    
    isservicesadtr = False
    isidentitysettings = False
    isdstadtrtranslated = False
    # this can be either accept, crop, user_auth or
    # client_auth in the security rule
    rule_action_type = None 
    lasttagqueue = collections.deque([],2)
    # REPORT METHODS

    def get_sec_rule_count(self):
        return len(self.sec_rules)

    def get_nat_rule_count(self):
        return len(self.nat_rules)

    def get_all_sec_rules(self):
        return self.sec_rules

    def get_all_nat_rules(self):
        return self.nat_rules

    def get_sec_allow_rule_count(self):
        return len(self.allow_rules)
    
    def get_sec_deny_rule_count(self):
        return len(self.deny_rules)

    def _get_line(self, fp):
        i = fp.readline()
        logging.info("Processing " + i)
        if i == '':
            return None
        else:
            i = i.strip()
            if re.search(r'\(', i):
                self.parenest += 1
            if re.search(r'\)', i):
                self.parenest -= 1
            return i

    def _get_matchstr(self, linestr):
        matchobj = re.match(r':\s*\(?"?([a-zA-z@_0-9\-\s\.]+)?"?', linestr)
        matchstr = None
        if matchobj and matchobj.group(1) is not None:
            matchstr = matchobj.group(1).strip()
        # we use isgate to append or create keys in the
        # parent datastructure like op, compound, referenceobject
        # or Any tag. Once we hit the closing parentheses, we make
        # isgate to False
        if not self.isgate:
            self.lasttagqueue.append(matchstr)
            
        if self.lasttagqueue[0] is not None:
            self.lasttag = self.lasttagqueue[0]
        else:
            self.lasttag = self.lasttagqueue[1]
        return (matchstr, matchobj)

    def __init__(self, filepath):
        fp = open(filepath, 'r')
        while True:
            i = self._get_line(fp)
            if i is None:
                break
            # here we check if we are reading the file
            # for the first time
            if self.uid is None:
                # this is the match for the global id, the config
                # file starts with '(' and ends with ')'
                if re.match(r'^\(', i):
                    self.isparse = True
                    # get the global 'uid' for this config file
                    matchobj = re.match(r'\("##(.*)?"', i)
                    if matchobj:
                        self.uid = matchobj.group(1)
                        self.glbl[matchobj.group(1)] = {}
                        continue
                else:
                    logstr = """The config file is corrupt, 
                                the file does not start with '(' !!"""
                    logging.error(logstr)
                    sys.exit(1)

            # always check if are reading a valid file
            if len(self.glbl) > 0 and self.isparse:
                (matchstr, matchobj) = self._get_matchstr(i)
                if matchstr == 'use_VPN_communities':
                    mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                    self.glbl[self.uid]['use_VPN_communities'] = mobj.group(2)
                    continue
                ################################################################                
                #                   SECURITY RULE                              #
                ################################################################
                if matchstr == 'rule':
                    logging.info("New rule (Security) seen!")                    
                    if 'rules' not in self.glbl[self.uid]:
                        self.glbl[self.uid]['rules'] = []
                    self.glbl[self.uid]['rules'].append(self._read_rule(fp))
                    self.crc += 1                    
                    continue
                ################################################################                
                #                   RULE ADTR                                  #
                ################################################################
                if matchstr == 'rule_adtr':
                    logging.info("New rule_adtr (NAT) seen!")                    
                    if 'rules_adtr' not in self.glbl[self.uid]:
                        self.glbl[self.uid]['rules_adtr'] = []
                    self.glbl[self.uid]['rules_adtr'].append(self._read_rule_adtr(fp))
                    self.crac += 1
                    continue
                ################################################################
                #                  HEADER INFO                                 #  
                ################################################################
                if matchstr in ['default', 'globally_enforced',
                                'queries', 'queries_adtr']:
                    try:
                        mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                        self.glbl[self.uid][matchstr] = mobj.group(2)
                    except AttributeError, e:
                        self.glbl[self.uid][matchstr] = ''
                    continue

                if matchstr == 'collection':
                    self.glbl[self.uid]['collection'] = {'ReferenceObject': self._read_refobj(fp)}
                    continue

                if matchstr == 'AdminInfo':
                    self.glbl[self.uid]['AdminInfo'] = self._read_admin_info(fp)
                    continue

                if i == ')':
                    self.isparse = False
                    if self.parenest == 0:
                        logging.info("CHKP file has been successfully parsed!")
                    else:
                        logstr = """CHKP file wasn't parsed successfully!
                                    Paren count is {0}, should be 0""".format(str(self.parenest))
                        logging.error(logstr)
        fp.close()
        if 'rules' in self.glbl[self.uid]:
            self.sec_rules = self.glbl[self.uid]['rules']
        else:
            self.sec_rules = []
        if 'rules_adtr' in self.glbl[self.uid]:
            self.nat_rules = self.glbl[self.uid]['rules_adtr']
        else:
            self.nat_rules = []
        
                    
    def _read_admin_info(self, fp):
        ds = {}
        while True:
            i = self._get_line(fp)
            if i is None:
                return None 
            (matchstr, matchobj) = self._get_matchstr(i)            
            if matchstr == 'chkpf_uid':
                mobj = re.match(r':(\w+)?\s*\("\{(.*)?\}"\)', i)
                ds['chkpf_uid'] = mobj.group(2)
                continue
            if matchstr == 'ClassName':
                mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                if mobj.group(2) not in self.ccn:
                    logstr = """Unknown chkp class name in AdminInfo {0}
                                please update the class names!""".format(mobj.group(2))
                    logging.warning(logstr)
                ds['ClassName'] = mobj.group(2)
                continue
            if matchstr in ['table', 'icon']:
                mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                ds[matchstr] = mobj.group(2)
                continue
            if matchstr == 'LastModified':
                self.islastmodified = True
                ds['LastModified'] = {}
                continue

            if self.islastmodified:
                if matchstr == 'Time':
                    mobj = re.match(r':(\w+)?\s*\("(.*)"\)', i)
                    ds['LastModified']['Time'] = mobj.group(2)
                    continue
                if matchstr in ['last_modified_utc', 'By', 'From']:
                    mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                    ds['LastModified'][matchstr] = mobj.group(2)
                    continue
                if i == ')':
                    self.islastmodified = False
                    continue
            if i == ')':
                self.isadmininfo = False
                break
        return ds
            
    def _read_chkp_object(self, fp):
        ds = {}
        while True:
            i = self._get_line(fp)
            if i is None:
                logstr = """Get EOF while parsing 
                            install / services / src / through / dst 
                            object in the _read_chkp_object!!"""
                logging.error(logstr)
                return None
            (matchstr, matchobj) = self._get_matchstr(i)            
            if matchstr == 'AdminInfo':
                ds['AdminInfo'] = self._read_admin_info(fp)
                continue
            if matchstr in ['compound', 'op']:
                # check if really need to call the method, else
                # be done with it
                try:
                    mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                    ds[matchstr] = mobj.group(2)
                    continue
                except AttributeError, e:
                    ds[matchstr] = {}
                if re.search(r'(?!\(\))', i):
                    ds[matchstr] = self._read_compound_compound(fp)
                    continue
            if matchstr == 'ReferenceObject':
                self.isgate = True
                ds[self.lasttag + "_values"] = []
                temp = {}
                temp['ReferenceObject'] = self._read_refobj(fp)
                ds[self.lasttag + "_values"].append(temp)
                continue
            if re.search(r'Any', i):
                self.isgate = True
                ds[self.lasttag + "_values"] = [self._read_anycompoundobj(fp)]
                continue
            if not re.match(r'[\(|\)]', i):
                self.isgate = True
                if self.lasttag + "_values" in ds:
                    ds[self.lasttag + "_values"].append(matchstr)
                else:
                    ds[self.lasttag + "_values"] = []
                    ds[self.lasttag + "_values"].append(matchstr)
                continue
            if i == ")":
                self.isgate = False
                parenttag = None
                break
        return ds
    
    def _read_refobj(self, fp):
        ds = {}
        while True:
            i = self._get_line(fp)
            if i is None:
                logging.error('Get EOF while parsing reference object!!')
                return None
            (matchstr, matchobj) = self._get_matchstr(i)
            # there is no difference between getting info for name and table attributes
            if matchstr in ['Name', 'Table' , 'Uid']:
                try:
                    mobj = re.match(r':(\w+)?\s*\(("\{)?([a-zA-Z0-9\-_\.]+)?(\}")?\)', i)
                    if matchstr == 'Uid':
                        ds[matchstr] = mobj.group(3)
                    else:
                        ds[matchstr] = mobj.group(2)
                except AttributeError, e:
                    ds[matchstr] = None
                continue
            if i == ")":
                break
        return ds

    def _read_compound_compound(self, fp):
        ds = {}
        while True:
            i = self._get_line(fp)
            if i is None:
                logging.error('Get EOF while parsing compound compound object!!')                
                return None
            (matchstr, matchobj) = self._get_matchstr(i)
            if re.search(r'usr\-', i):
                ds[matchstr] = {}
                self.isusr = True
                continue
            if self.isusr:
                self.isgate = True
                if matchstr == 'AdminInfo':
                    ds[self.lasttag][matchstr] = self._read_admin_info(fp)
                    continue
                if matchstr == 'at':
                    if re.search(r'Any', i):
                        ds[self.lasttag]['at'] = []
                        ds[self.lasttag]['at'].append(self._read_anycompoundobj(fp))
                        continue
                if matchstr in ['type', 'color']:
                    try:
                        mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                        ds[self.lasttag][matchstr] = mobj.group(2)
                    except AttributeError, e:
                        ds[self.lasttag][matchstr] = {}
                    continue
                if i == ")":
                    self.isusr = False
                    self.isgate = False
                    continue
            if i == ")":
                break
        return ds

    def _read_anycompoundobj(self, fp):
        ds = {}
        while True:
            i = self._get_line(fp)
            if i is None:
                logging.error('Get EOF while parsing ANY compound object!!')                
                return None
            (matchstr, matchobj) = self._get_matchstr(i)
            if matchstr == 'color':
                mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                ds['Any'] = {'color': mobj.group(2)}
                continue
            if i == ")":
                break
        return ds
    
    def _read_rule(self, fp):
        ds = {}
        rule_action_type = None
        parenttag = None
        while True:
            i = self._get_line(fp)
            if i is None:
                logging.error('Get EOF while parsing a rule object!!')                                                
                return None
            (matchstr, matchobj) = self._get_matchstr(i)
            if matchstr == 'action' and not self.isaction:
                self.isaction = True
                ds['action'] = {}
                continue
            if self.isaction:
                if matchstr in ['drop',
                                'accept',
                                'User Auth',
                                'Client Auth']:
                    # isaccept flag is common for all actions
                    self.isaccept = True
                    rule_action_type = matchstr
                    # this is just for convinience sake, DONOT report this
                    # while displaying, use it internally
                    ds['action'] = {rule_action_type: {},'_policy_type': rule_action_type}
                    continue
                if self.isaccept:
                    if matchstr == 'options':
                        self.isoptions = True
                        ds['action'][rule_action_type]['options']= {}
                        continue
                    if self.isoptions:
                        if matchstr == 'AdminInfo':
                            self.isadmininfo = True
                            ds['action'][rule_action_type]['options']['AdminInfo'] = self._read_admin_info(fp)
                            continue
                        if re.match(r':(\w+)?\s*\((.*)\)', i):
                            mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                            try:
                                ds['action'][rule_action_type]['options'][matchstr] = mobj.group(2)
                            except AttributeError, e:
                                ds['action'][rule_action_type]['options'][matchstr] = {}
                                continue
                        if i == ")":
                            self.isoptions = False
                            continue
                    if matchstr in ['clauth_track', 'accept_track']:
                        parenttag = matchstr
                        self.isclauthtrack = True
                        ds['action'][rule_action_type][matchstr] = {'Auth': {}}
                        continue
                    if self.isclauthtrack:
                        if i == ")":
                            self.isclauthtrack = False
                            continue
                        if re.match(r':([a-zA-Z0-9\-_@\.]+)?\s*\((.*)\)', i):
                            mobj = re.match(r':([a-zA-Z0-9\-_@\.]+)?\s*\((.*)\)', i)
                            try:
                                t1 = mobj.group(1).strip()
                                t2 = mobj.group(2).strip()
                                ds['action'][rule_action_type][parenttag]['Auth'][t1] = t2
                            except AttributeError, e:
                                ds[self.crc]['action'][rule_action_type][parenttag]['Auth'][t1] = {}
                            continue
                        # this action is different from the compound
                        # action, which is a top-level attribute for rule    
                    if matchstr == 'action':
                        try:
                            mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                            ds['action'][rule_action_type]['action'] = mobj.group(2)
                        except AttributeError, e:
                            ds['action'][rule_action_type]['action'] = ''
                        continue
                    if matchstr == 'identity_settings':
                        self.isidentitysettings = True
                        ds['action'][rule_action_type]['identity_settings'] = {}
                        continue
                    if self.isidentitysettings:
                        if matchstr == 'AdminInfo':
                            ds['action'][rule_action_type]['identity_settings']['AdminInfo'] = self._read_admin_info(fp)
                            continue
                        if matchstr in ['type',
                                        'allow_ad_query',
                                        'allowed_sources',
                                        'allow_captive_portal',
                                        'allow_identity_agent',
                                        'require_packet_tagging',                                                    
                                        'redirect_to_captive_portal']:
                            mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                            ds['action'][rule_action_type]['identity_settings'][matchstr] = mobj.group(2)
                            continue
                        if i == ")":
                            self.isidentitysettings = False
                            continue
                                                    
                    if matchstr in ['type',
                                    'macro',
                                    'src_options']:
                        try:
                            mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                            ds['action'][rule_action_type][matchstr] = mobj.group(2)
                        except AttributeError, e:
                            ds['action'][rule_action_type][matchstr] = {}
                        continue
                    if matchstr == 'AdminInfo':
                        ds['action'][rule_action_type]['AdminInfo'] = self._read_admin_info(fp)
                        continue
                                    
                    if i == ")":
                        self.isaccept = False
                        continue
                if i == ")":
                    self.isaction = False
                    continue
                                                        
            if matchstr in ['name',
                            'disabled',
                            'dst_options',
                            'global_location']:
                try:
                    mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                    ds[matchstr] = mobj.group(2)
                except AttributeError, e:
                    ds[matchstr] = None
                continue
            if matchstr == 'time':
                try:
                    self.istime = True
                    ds['time'] = []
                except AttributeError, e:
                    ds['time'] = None
                continue
            if self.istime:
                if re.search(r'Any', i):
                    ds['time'].append(self._read_anycompoundobj(fp))
                    continue
                if i == ")":
                    self.istime = False
                    continue
            if matchstr == 'track':
                self.istrack = True
                ds['track'] = []
                continue
            if self.istrack:
                if not re.match(r'[\(|\)]', i):
                    ds['track'].append(matchstr)
                    continue
                if i == ")":
                    self.istrack = False
                    continue
            ############################################################
            #          DST / INSTALL / SRC / THROUGH / SERVICES        #
            ############################################################
                                    
            if matchstr in ['dst', 'install', 'src', 'through', 'services']:
                # we will call the same function for the above 5
                # objects
                ds[matchstr] = self._read_chkp_object(fp)
                continue
            if matchstr == 'unified_rulenum':
                mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                ds['unified_rulenum'] = mobj.group(2)
                logging.info("RULE " + str(mobj.group(2)))
                continue
            if matchstr == 'AdminInfo':
                ds['AdminInfo'] = self._read_admin_info(fp)
                continue
            if i == ")":
                break
        if rule_action_type == 'accept':
            self.allow_rules.append(ds)
        elif rule_action_type == 'drop':
            self.deny_rules.append(ds)
        elif rule_action_type in ['User Auth', 'Client Auth']:
            if ds['action'][rule_action_type]['action'] == 'accept':
                self.allow_rules.append(ds)
            elif ds['action'][rule_action_type]['action'] == 'drop':
                self.allow_rules.append(ds)
        return ds
    
    def _read_rule_adtr(self, fp):
        ds = {}
        # see below to what this does
        parenttag = None
        while True:
            i = self._get_line(fp)
            if i is None:
                logging.error('Get EOF while parsing a rule_adtr object!!')                
                return None
            (matchstr, matchobj) = self._get_matchstr(i)            
            # if there are many rule_adtrs, make the following a list
            # of dicts, with the counter as the indx into the list

            if matchstr == 'disabled':
                mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)                        
                ds['disabled'] = mobj.group(2)
                continue
            if matchstr in ['dst_adtr', 'install', 'src_adtr']:
                self.isdstadtr = True
                ds[matchstr] = {}
                continue
            if self.isdstadtr:
                self.isgate = True                
                if re.match(':', i):
                    mobj = re.match(r':\s*(.*)?', i)
                    ds[self.lasttag] = mobj.group(1)
                    continue
                if i == ")":
                    self.isdstadtr = False
                    self.isgate = False
                    continue
            if matchstr in ['name', 'rule_block_number', 'global_location']:
                try:
                    mobj = re.match(r':(\w+)?\s*\((.*)?\)', i)
                    ds[matchstr] = mobj.group(2)
                except AttributeError, e:
                    ds[matchstr] = {}
                continue
            if matchstr == 'services_adtr':
                self.isservicesadtr = True
                ds['services_adtr'] = []
                continue
            if self.isservicesadtr:
                if re.search(r'Any', i):
                    ds['services_adtr'].append(self._read_anycompoundobj(fp))
                    continue
                if i == ")":
                    self.isservicesadtr = False
                    continue
                                            
            ############################################################
            #         DST_ADTR_TRANSLATED / SERVICES_ADTR_TRANSLATED   #
            ############################################################
            
            if matchstr in ['dst_adtr_translated',
                            'services_adtr_translated',
                            'src_adtr_translated']:
                # we use isdstadtrtranslated for both
                # dst_adtr_translated and services_adtr_translated
                # because this is just a flag
                self.isdstadtrtranslated = True
                # this is just an exception to the rule that
                # lasttag contains the grandparent tag
                # we need to think of a better way
                parenttag = matchstr
                ds[matchstr] = {}
                continue
            if self.isdstadtrtranslated:
                if matchstr == 'AdminInfo':
                    ds[parenttag] = {'AdminInfo': self._read_admin_info(fp)}
                    continue
                if matchstr == 'adtr_method':
                    mobj = re.match(r':(\w+)?\s*\((.*)\)', i)
                    ds[parenttag]['adtr_method'] = mobj.group(2)
                    continue
                if re.search(r"Any", i):
                    self.isgate = True
                    ds[parenttag][self.lasttag + "_values"] = []
                    ds[parenttag][self.lasttag + "_values"].append(self._read_anycompoundobj(fp))
                    continue
                # this is a value, basically don't have any parentheses here
                if re.search(r':\s+(.*)?', i):
                    mobj = re.match(r':\s+(.*)?', i)                    
                    ds[parenttag][self.lasttag + "_values"] = []
                    try:
                        ds[parenttag][self.lasttag + "_values"].append(mobj.group(1))
                    except AttributeError, e:
                        logging.error("Could not get any value from {0} in _read_rule_adtr func".format(i))
                    continue
                if i == ")":
                    self.isdstadtrtranslated = False
                    parenttag = None
                    self.isgate = False                                        
                    continue
            if matchstr == 'AdminInfo':
                ds['AdminInfo'] = self._read_admin_info(fp)
                continue
            if i == ")":
                break
        return ds

if __name__ == '__main__':
    chkpfile = panfile = None
    if len(sys.argv) < 2:
       print """
==========================================================================
USAGE: chkp_pan_cfg_diff.py <path/to/CHKP cfg file> <path/to/PAN cfg file>
==========================================================================
             """
       sys.exit(1)
    chkpfile = sys.argv[1]
    panfile = sys.argv[2]
    # check if chkpfile exists
    for i in [chkpfile, panfile]:
        if not os.path.isfile(i):
            print "ERROR: {0} path cannot be found".format(i)
            sys.exit(1)

    chkpds = CHKP_Parse(chkpfile)
    pands = PAN_Parse(panfile)
    chkpnrc = str(chkpds.get_nat_rule_count())
    pannrc = str(pands.get_nat_rule_count())
    chkpsrc = str(chkpds.get_sec_rule_count())
    pansrc = str(pands.get_sec_rule_count())
    chkparc = str(chkpds.get_sec_allow_rule_count())
    panarc = str(pands.get_sec_allow_rule_count())
    chkpdrc = str(chkpds.get_sec_deny_rule_count())
    pandrc = str(pands.get_sec_deny_rule_count())
    
    while True:
        x = sp.call('clear', shell = True)
        fmtstr1 = """

=================================================================
                  Checkpoint - Palo Alto Networks 
                  -------------------------------
                 Configuration Parser & Comparator    
=================================================================
CHKP File: {8} 
PAN File:  {9}
---------------------------------------------------------------
                           Summary                             
---------------------------------------------------------------

                         PAN          CHKP

# NAT Rules              {0:<13}{1:<13}
# SEC Rules              {2:<13}{3:<13} 
# Allow policies         {4:<13}{5:<13} 
# Deny policies          {6:<13}{7:<13} 
---------------------------------------------------------------

1) Show me the NAT rules in PAN config file
2) Show me the NAT rules in CHKP config file
3) Show me the SEC rules in PAN config file
4) Show me the SEC rules in CHKP config file
5) Compare the NAT rules of CHKP and PAN files
6) Compare the SEC rules of CHKP and PAN files
7) Compare the SEC/DENY rules of CHKP and PAN files
8) Exit


ENTER your choice: """
        print fmtstr1.format(pannrc, chkpnrc, pansrc, chkpsrc, panarc, chkparc, pandrc, chkpdrc, sys.argv[1], sys.argv[2])
        choice = None
        try:
            choice = int(raw_input())
        except ValueError, e :
            continue
        if choice == 1:
            print "NAT rules of PAN are: "
            for i in pands.get_all_nat_rules():
                print """
=====================================================
                """
                print str(i)
                print """
=====================================================
                """
        if choice == 2:
            print "NAT rules of CHKP are: "
            for i in chkpds.get_all_nat_rules():
                print """
=====================================================
                """
                print str(i)
                print """
=====================================================
                """
        if choice == 3:
            print "SEC rules of PAN are: "
            for i in pands.get_all_sec_rules():
                print """
=====================================================
                """
                print str(i)
                print """
=====================================================
                """
        if choice == 4:
            print "SEC rules of CHKP are: "
            for i in chkpds.get_all_sec_rules():
                print """
=====================================================
                """
                print str(i)
                print """
=====================================================
                """
        if choice == 5:
            cnr = chkpds.get_all_nat_rules()
            pnr = pands.get_all_nat_rules()
            print "CHKP and PAN NAT Rules: "
            if chkpds.get_nat_rule_count() > 0:
                if pands.get_nat_rule_count() == chkpds.get_nat_rule_count():
                    formatstr = """
-----------------------------------------------------------------------------------------
|                        CHKP                                         PAN               |
-----------------------------------------------------------------------------------------
Rule:                    {0:<45}{1:<45}
Source Zone:             {2:<45}{3:<45}
Dest Zone:               {4:<45}{5:<45}
Source Address:          {6:<45}{7:<45}
Dest Address             {8:<45}{9:<45}
Services                 {10:<45}{11:<45}
Translation:             {12:<45}{13:<45}
Translated Address       {14:<45}{15:<45}           
==========================================================================================
"""                
                    for i in xrange(0, pands.get_nat_rule_count()):
                        print formatstr.format(i + 1,
                                               pnr[i]['rule_num'],
                                               'NA',
                                               pnr[i]['from'],
                                               'NA',
                                               pnr[i]['to'],
                                               cnr[i]['src_adtr'],
                                               pnr[i]['source'],
                                               cnr[i]['dst_adtr'],
                                               pnr[i]['dest'],
                                               cnr[i]['services_adtr'],
                                               pnr[i]['service'],
                                               cnr[i]['src_adtr_translated']['AdminInfo']['ClassName'],
                                               pnr[i]['translation_type'],
                                               cnr[i]['src_adtr_translated']['adtr_method_values'],
                                               pnr[i]['translation_address'])
            else:
                print "There are NO NAT rules in CHKP"
                if pands.get_nat_rule_count() == 0:
                    print "...similar is the case with the PAN"
                                          
        if choice == 6:
            csr = chkpds.get_all_sec_rules()
            psr = pands.get_all_sec_rules()
            print "CHKP and PAN SEC Rules: "
            if pands.get_sec_rule_count() == chkpds.get_sec_rule_count():
               formatstr = """
-----------------------------------------------------------------------------------------
|                        CHKP                                         PAN               |
-----------------------------------------------------------------------------------------
Rule:                    {0:<45}{1:<45}
Source Zone:             {2:<45}{3:<45}
Dest Zone:               {4:<45}{5:<45}
Source Address:          {6:<45}
Dest Address             {7:<45}
User Access Enabled:     {8:<45}{9:<45}
Application:             {10:<45}{11:<45}
Services                 {12}
Policy Action:           {13:<45}{14:<45}
==========================================================================================
"""                
               for i in xrange(0, pands.get_sec_rule_count()):
                   print formatstr.format(csr[i]['unified_rulenum'],
                                          psr[i]['rule_num'],
                                          'NA', psr[i]['source_zone'],
                                          'NA', psr[i]['dest_zone'],
                                          disply(csr[i]['src'], psr[i]['source_address']),
                                          disply(csr[i]['dst'], psr[i]['dest_address']),
                                          'NA',
                                          psr[i]['user_access_enabled'],
                                          'NA',
                                          psr[i]['application'],
                                          disply(csr[i]['services'], psr[i]['services']),
                                          csr[i]['action']['_policy_type'],
                                          psr[i]['action'])
                   print "press enter to see more...."
                   k = raw_input()
        if choice == 7:
            csr = chkpds.deny_rules
            psr = pands.deny_rules_list
            print "CHKP and PAN SEC/DENY Rules: "
            count = 0
            if len(csr) > len(psr):
                count = len(csr)
            if len(psr) > len(csr):
                count = len(psr)
            if len(psr) == len(csr):
                count = len(psr)
            formatstr = """
-----------------------------------------------------------------------------------------
|                        CHKP                                         PAN               |
-----------------------------------------------------------------------------------------
Rule:                    {0:<45}{1:<45}
Source Zone:             {2:<45}{3:<45}
Dest Zone:               {4:<45}{5:<45}
Source Address:          {6:<45}
Dest Address             {7:<45}
User Access Enabled:     {8:<45}{9:<45}
Application:             {10:<45}{11:<45}
Services                 {12}
Policy Action:           {13:<45}{14:<45}
==========================================================================================
"""                
            for i in xrange(0, count):
                try:
                    print formatstr.format(csr[i]['unified_rulenum'],
                                           psr[i]['rule_num'],
                                           'NA', psr[i]['source_zone'],
                                           'NA', psr[i]['dest_zone'],
                                           disply(csr[i]['src'], psr[i]['source_address']),
                                           disply(csr[i]['dst'], psr[i]['dest_address']),
                                           'NA',
                                           psr[i]['user_access_enabled'],
                                           'NA',
                                           psr[i]['application'],
                                           disply(csr[i]['services'], psr[i]['services']),
                                           csr[i]['action']['_policy_type'],
                                           psr[i]['action'])
                except:
                    if i >= len(csr):
                        print formatstr.format('NA',
                                           psr[i]['rule_num'],
                                           'NA', psr[i]['source_zone'],
                                           'NA', psr[i]['dest_zone'],
                                           "{0:<45}{1:<45}".format('NA', psr[i]['source_address']),
                                           "{0:<45}{1:<45}".format('NA', psr[i]['dest_address']),
                                           'NA',
                                           psr[i]['user_access_enabled'],
                                           'NA',
                                           psr[i]['application'],
                                          "{0:<45}{1:<45}".format('NA', psr[i]['services']),
                                           "NA",
                                           psr[i]['action'])
                    if i >= len(psr):
                        print formatstr.format(csr[i]['unified_rulenum'],
                                               "NA",
                                               'NA', "NA",
                                               'NA', "NA",
                                               "{0:<45}{1:<45}".format(csr[i]['src'], 'NA'),
                                               "{0:<45}{1:<45}".format(csr[i]['dst'], 'NA'),
                                               'NA',
                                               'NA',
                                               'NA',
                                               'NA',
                                               "{0:<45}{1:<45}".format(csr[i]['services'], 'NA'),
                                               csr[i]['action']['_policy_type'],
                                               'NA')
                        
                print "press enter to see more...."
                k = raw_input()
                   
        if choice == 8:
            sys.exit(1)
        print "press enter..."
        k = raw_input()
