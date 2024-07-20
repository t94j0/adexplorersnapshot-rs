use crate::guid::GUID;
use crate::parser::{AttributeValue, Object};
use crate::sid::SID;
use std::collections::{HashMap, HashSet};

use super::parser::Snapshot;

pub trait Cache<K, V> {
    fn get(&self, key: &K) -> Option<&V>;
    fn insert(&mut self, key: K, value: V);
}

#[derive(Debug)]
pub struct SIDCache {
    cache: HashMap<SID, usize>,
}

impl Cache<SID, usize> for SIDCache {
    fn get(&self, key: &SID) -> Option<&usize> {
        self.cache.get(key)
    }

    fn insert(&mut self, key: SID, value: usize) {
        self.cache.insert(key, value);
    }
}

#[derive(Debug)]
pub struct DNCache {
    cache: HashMap<String, usize>,
}

impl DNCache {
    pub fn get(&self, key: &String) -> Option<&usize> {
        self.cache.get(&key.to_uppercase())
    }

    pub fn insert(&mut self, key: String, value: usize) {
        self.cache.insert(key.to_uppercase(), value);
    }

    pub fn get_ou_children(&self, ou_dn: &str) -> Vec<usize> {
        let ou_dn_upper = ou_dn.to_uppercase();
        let ou_prefix = format!(",{}", ou_dn_upper);
        let mut children = HashSet::new();

        for (dn, &index) in &self.cache {
            if dn != &ou_dn_upper && (dn.ends_with(&ou_prefix) || dn == &ou_dn_upper) {
                let relative_dn = &dn[..dn.len() - ou_dn_upper.len()];
                if relative_dn.matches(',').count() <= 1 {
                    children.insert(index);
                }
            }
        }

        children.into_iter().collect()
    }
}

#[derive(Debug)]
pub struct ComputerCache {
    cache: HashMap<String, usize>,
}

impl ComputerCache {
    pub fn get(&self, key: &String) -> Option<&usize> {
        self.cache.get(&key.to_uppercase())
    }

    pub fn insert(&mut self, key: String, value: usize) {
        self.cache.insert(key.to_uppercase(), value);
    }

    pub fn contains_key(&self, key: &String) -> bool {
        self.cache.contains_key(&key.to_uppercase())
    }
}

#[derive(Debug)]
pub struct ObjectTypeGUIDCache {
    cache: HashMap<usize, GUID>,
}

impl Cache<usize, GUID> for ObjectTypeGUIDCache {
    fn get(&self, key: &usize) -> Option<&GUID> {
        self.cache.get(key)
    }

    fn insert(&mut self, key: usize, value: GUID) {
        self.cache.insert(key, value);
    }
}

#[derive(Debug)]
pub struct ClassCache {
    cache: HashMap<String, usize>,
}

impl Cache<String, usize> for ClassCache {
    fn get(&self, key: &String) -> Option<&usize> {
        self.cache.get(key)
    }

    fn insert(&mut self, key: String, value: usize) {
        self.cache.insert(key, value);
    }
}

#[derive(Debug)]
pub struct DomainCache {
    domains: HashMap<String, usize>,
}

impl DomainCache {
    fn new() -> Self {
        DomainCache {
            domains: HashMap::new(),
        }
    }

    fn insert_domain(&mut self, dn: String, idx: usize) {
        self.domains.insert(dn, idx);
    }

    fn insert_forest_domain(&mut self, ncname: String, idx: usize) {
        if !self.domains.contains_key(&ncname) {
            self.domains.insert(ncname, idx);
        }
    }
}

#[derive(Debug)]
pub struct CertificateTemplateCache {
    templates: HashMap<String, HashSet<String>>,
}

impl CertificateTemplateCache {
    fn new() -> Self {
        CertificateTemplateCache {
            templates: HashMap::new(),
        }
    }

    fn insert(&mut self, template: String, name: String) {
        self.templates
            .entry(template)
            .or_insert_with(HashSet::new)
            .insert(name);
    }

    fn _get(&self, template: &str) -> Option<&HashSet<String>> {
        self.templates.get(template)
    }
}

#[derive(Debug)]
pub struct Caches {
    pub root_domain: Option<String>,
    pub domain_sid: Option<SID>,
    pub sid_cache: SIDCache,
    pub dn_cache: DNCache,
    pub computer_cache: ComputerCache,
    pub object_type_guid_cache: ObjectTypeGUIDCache,
    pub class_cache: ClassCache,
    pub domain_cache: DomainCache,
    pub domain_controllers: Vec<usize>,
    pub certificate_template_cache: CertificateTemplateCache,
}

impl Caches {
    pub fn new() -> Self {
        Caches {
            root_domain: None,
            domain_sid: None,
            sid_cache: SIDCache {
                cache: HashMap::new(),
            },
            dn_cache: DNCache {
                cache: HashMap::new(),
            },
            computer_cache: ComputerCache {
                cache: HashMap::new(),
            },
            object_type_guid_cache: ObjectTypeGUIDCache {
                cache: HashMap::new(),
            },
            class_cache: ClassCache {
                cache: HashMap::new(),
            },
            domain_cache: DomainCache::new(),
            domain_controllers: Vec::new(),
            certificate_template_cache: CertificateTemplateCache::new(),
        }
    }

    pub fn build_caches(&mut self, snapshot: &Snapshot) {
        self.build_object_type_guid_cache(snapshot);
        self.build_class_cache(snapshot);
        self.build_object_caches(snapshot);
    }

    fn build_object_type_guid_cache(&mut self, snapshot: &Snapshot) {
        // Build cache from classes
        for (i, cl) in snapshot.classes.iter().enumerate() {
            self.object_type_guid_cache
                .insert(i, cl.schema_id_guid.clone());
        }

        // Build cache from properties
        for (i, p) in snapshot.properties.iter().enumerate() {
            self.object_type_guid_cache
                .insert(i, p.schema_id_guid.clone());
        }
    }

    fn build_class_cache(&mut self, snapshot: &Snapshot) {
        for (index, class) in snapshot.classes.iter().enumerate() {
            // Store by class name
            self.class_cache.insert(class.class_name.clone(), index);

            // Store by DN
            self.class_cache.insert(class.dn.clone(), index);

            // Store by CN (first part of DN)
            if let Some(cn) = class
                .dn
                .split(',')
                .next()
                .and_then(|part| part.split('=').nth(1))
            {
                self.class_cache.insert(cn.to_string(), index);
            }
        }
    }

    fn build_object_caches(&mut self, snapshot: &Snapshot) {
        for (idx, obj) in snapshot.objects.iter().enumerate() {
            // Build SID cache
            let sid = Self::get_object_sid(obj);
            if let Some(sid) = sid.as_ref() {
                self.sid_cache.insert(sid.clone(), idx);
            }

            // Build DN cache
            if let Some(dn) = Self::get_object_dn(obj) {
                self.dn_cache.insert(dn, idx);
            }

            if let Some(classes) = obj.get_attribute_classes() {
                let lowercase_classes: Vec<String> =
                    classes.iter().map(|s| s.to_lowercase()).collect();

                // Build Domain cache
                if lowercase_classes.contains(&"domain".to_string()) {
                    self.root_domain = Self::get_object_dn(obj);
                    self.domain_sid = sid.clone();
                    if let Some(dn) = Self::get_object_dn(obj) {
                        self.domain_cache.insert_domain(dn, idx);
                    }
                }

                // Build Forest Domain cache
                if lowercase_classes.contains(&"crossref".to_string()) {
                    if let Some(system_flags) = self.get_attribute_value::<u32>(obj, "systemFlags")
                    {
                        if system_flags & 2 == 2 {
                            if let Some(ncname) = self.get_attribute_value::<String>(obj, "nCName")
                            {
                                self.domain_cache.insert_forest_domain(ncname, idx);
                            }
                        }
                    }
                }

                // Build Certificate Template cache
                if lowercase_classes.contains(&"pkienrollmentservice".to_string()) {
                    if let Some(name) = self.get_attribute_value::<String>(obj, "name") {
                        if let Some(templates) =
                            self.get_attribute_value::<Vec<String>>(obj, "certificateTemplates")
                        {
                            for template in templates {
                                self.certificate_template_cache
                                    .insert(template, name.clone());
                            }
                        }
                    }
                }
            }

            if Self::is_computer(obj) {
                if let Some(dnshostname) = Self::get_object_dnshostname(obj) {
                    self.computer_cache.insert(dnshostname, idx);
                }
                if let Some(name) = Self::get_object_name(obj) {
                    self.computer_cache.insert(name, idx);
                }
            }

            if let Some(uac) = self.get_attribute_value::<u32>(obj, "userAccountControl") {
                if uac & 0x2000 == 0x2000 {
                    self.domain_controllers.push(idx);
                }
            }
        }
    }

    fn is_computer(obj: &Object) -> bool {
        obj.attributes
            .get("sAMAccountType")
            .and_then(|attr| {
                if let Some(AttributeValue::Integer(account_type)) = attr.values.first() {
                    Some(*account_type == 805306369)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }

    fn get_attribute_value<T: FromAttributeValue>(
        &self,
        obj: &Object,
        attr_name: &str,
    ) -> Option<T> {
        obj.attributes.get(attr_name).and_then(|attr| {
            attr.values
                .first()
                .and_then(|value| T::from_attribute_value(value))
        })
    }

    fn get_object_sid(obj: &Object) -> Option<SID> {
        obj.attributes.get("objectSid").and_then(|attr| {
            if let Some(AttributeValue::OctetString(octet_string)) = attr.values.first() {
                SID::from_bytes(octet_string).ok()
            } else {
                None
            }
        })
    }

    fn get_object_dn(obj: &Object) -> Option<String> {
        obj.attributes.get("distinguishedName").and_then(|attr| {
            if let Some(AttributeValue::String(dn)) = attr.values.first() {
                Some(dn.clone())
            } else {
                None
            }
        })
    }

    fn get_object_dnshostname(obj: &Object) -> Option<String> {
        obj.attributes.get("dNSHostName").and_then(|attr| {
            if let Some(AttributeValue::String(hostname)) = attr.values.first() {
                Some(hostname.clone())
            } else {
                None
            }
        })
    }

    fn get_object_name(obj: &Object) -> Option<String> {
        obj.attributes.get("name").and_then(|attr| {
            if let Some(AttributeValue::String(name)) = attr.values.first() {
                Some(name.clone())
            } else {
                None
            }
        })
    }
}

trait FromAttributeValue {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self>
    where
        Self: Sized;
}

impl FromAttributeValue for String {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self> {
        match value {
            AttributeValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

impl FromAttributeValue for i64 {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self> {
        match value {
            AttributeValue::LargeInteger(i) => Some(*i),
            _ => None,
        }
    }
}

impl FromAttributeValue for u32 {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self> {
        match value {
            AttributeValue::Integer(i) => Some(*i),
            _ => None,
        }
    }
}

impl FromAttributeValue for bool {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self> {
        match value {
            AttributeValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

impl FromAttributeValue for Vec<String> {
    fn from_attribute_value(value: &AttributeValue) -> Option<Self> {
        match value {
            AttributeValue::String(s) => Some(vec![s.clone()]),
            _ => None,
        }
    }
}
