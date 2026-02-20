import requests
import json

class GraphQLScanner:
    """
    Expert GraphQL Scanner.
    Detects GraphQL endpoints and attempts introspection to dump the schema.
    """
    def __init__(self, target):
        self.target = target
        self.endpoints = [
            "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql", 
            "/api/graphql", "/api/v1/graphql", "/query"
        ]
        # Standard introspection query
        self.introspection_query = {
            "query": """
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  description
                  locations
                  args {
                    ...InputValue
                  }
                }
              }
            }

            fragment FullType on __Type {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }

            fragment InputValue on __InputValue {
              name
              description
              type { ...TypeRef }
              defaultValue
            }

            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """
        }

    def _analyze_schema(self, schema):
        """
        V6 EXPERT: Analyzes a GraphQL schema to find sensitive objects,
        queries, and mutations.
        """
        analysis = {
            "high_value_queries": [],
            "high_value_mutations": [],
            "sensitive_fields": [],
            "admin_access": False
        }
        
        types = schema.get("types", [])
        risk_keywords = ["admin", "user", "login", "auth", "secret", "config", "debug", "delete", "remove", "update", "email", "password", "token"]
        
        for t in types:
            t_name = str(t.get("name", "")).lower()
            
            # Identify high value objects
            if any(kw in t_name for kw in risk_keywords):
                analysis["sensitive_fields"].append(t.get("name"))

            fields = t.get("fields") or []
            for f in fields:
                f_name = str(f.get("name", "")).lower()
                
                # Check for admin signals
                if "admin" in f_name or "admin" in t_name:
                    analysis["admin_access"] = True
                
                # Categorize based on parent type (Query vs Mutation)
                if t.get("name") == schema.get("queryType", {}).get("name"):
                    if any(kw in f_name for kw in risk_keywords):
                        analysis["high_value_queries"].append(f_name)
                elif t.get("name") == schema.get("mutationType", {}).get("name"):
                    if any(kw in f_name for kw in risk_keywords):
                        analysis["high_value_mutations"].append(f_name)

        return analysis

    def audit_graphql(self, port, protocol='http', logger=None):
        """
        Scans for GraphQL endpoints and probes for introspection.
        """
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        if logger: logger(f"GraphQL Expert: Auditing {len(self.endpoints)} potential endpoints on port {port}...", "INFO")

        for ep in self.endpoints:
            url = f"{base_url}{ep}"
            try:
                # 1. Check if endpoint exists
                r = requests.options(url, timeout=3, verify=False)
                if r.status_code not in [200, 405, 400]:
                    continue
                
                # 2. Attempt Introspection
                headers = {'Content-Type': 'application/json'}
                r_int = requests.post(url, json=self.introspection_query, headers=headers, timeout=5, verify=False)
                
                if r_int.status_code == 200 and "__schema" in r_int.text:
                    try:
                        resp_data = r_int.json().get("data", {})
                        schema_data = resp_data.get("__schema", {})
                        types_count = len(schema_data.get("types", []))
                        
                        # DEEP ANALYSIS
                        analysis = self._analyze_schema(schema_data)
                        
                        desc = f"The GraphQL endpoint at `{url}` has introspection enabled.\n\n"
                        desc += f"**Schema Stats**: {types_count} types discovered.\n"
                        
                        if analysis["high_value_queries"]:
                            desc += f"\n**Sensitive Queries**: `{', '.join(analysis['high_value_queries'][:10])}`"
                        if analysis["high_value_mutations"]:
                            desc += f"\n**Dangerous Mutations**: `{', '.join(analysis['high_value_mutations'][:10])}`"
                        
                        if analysis["admin_access"]:
                            desc += "\n\n⚠️ **CRITICAL SIGNAL**: Schema contains explicit 'Admin' management references."

                        findings.append({
                            "title": "GraphQL Introspection & Schema Leak",
                            "description": desc,
                            "severity": "high" if not analysis["admin_access"] else "critical",
                            "tool_source": "graphql_expert",
                            "raw_loot": json.dumps(schema_data)[:10000],
                            "loot_type": "GraphQL Schema"
                        })
                        
                        if logger: logger(f"📡 GRAPHQL VULN: Schema leaked at {url} ({types_count} types)", "WARN")
                    except Exception as e:
                        if logger: logger(f"GraphQL Parse Error: {e}", "DEBUG")
                    
                # 3. Check for GraphiQL (IDE)
                r_ide = requests.get(url, timeout=3, verify=False)
                if "GraphiQL" in r_ide.text or "graphql-playground" in r_ide.text.lower():
                    findings.append({
                        "title": "GraphQL IDE (GraphiQL/Playground) Exposed",
                        "description": f"An interactive GraphQL IDE was found at `{url}`.\nAccess: {url}",
                        "severity": "medium",
                        "tool_source": "graphql_expert"
                    })

            except Exception:
                continue

        return findings
