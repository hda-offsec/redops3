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
                r = requests.options(url, timeout=3, verify=True)
                if r.status_code not in [200, 405, 400]: # Some APIs return 400 for empty GraphQL POST
                    continue
                
                # 2. Attempt Introspection
                headers = {'Content-Type': 'application/json'}
                r_int = requests.post(url, json=self.introspection_query, headers=headers, timeout=5, verify=True)
                
                if r_int.status_code == 200 and "__schema" in r_int.text:
                    schema_data = r_int.json().get("data", {}).get("__schema", {})
                    types_count = len(schema_data.get("types", []))
                    
                    findings.append({
                        "title": "GraphQL Introspection Enabled",
                        "description": f"The GraphQL endpoint at `{url}` has introspection enabled. This allows an attacker to map the entire API schema, including hidden queries and mutations.\n\nDiscovered {types_count} types in schema.",
                        "severity": "high",
                        "tool_source": "graphql_expert",
                        "raw_loot": json.dumps(schema_data)[:5000],
                        "loot_type": "API Schema"
                    })
                    if logger: logger(f"📡 GRAPHQL VULN: Introspection enabled at {url}", "WARN")
                    
                # 3. Check for GraphiQL (IDE)
                r_ide = requests.get(url, timeout=3, verify=True)
                if "GraphiQL" in r_ide.text or "graphql-playground" in r_ide.text.lower():
                    findings.append({
                        "title": "GraphQL IDE (GraphiQL/Playground) Exposed",
                        "description": f"An interactive GraphQL IDE was found at `{url}`. This can be used to easily craft and execute queries against the API.",
                        "severity": "medium",
                        "tool_source": "graphql_expert"
                    })

            except Exception:
                continue

        return findings
