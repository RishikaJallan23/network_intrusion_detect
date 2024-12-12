MITIGATION_MEASURES = {
    'ddos': [
        "Deploy rate limiting to reduce traffic from offending IPs.",
        "Use Anycast to distribute traffic.",
        "Enable Web Application Firewalls (WAF).",
        "Monitor and analyze traffic patterns continuously."
    ],
    'scanning': [
        "Deploy intrusion detection systems to identify scanning patterns.",
        "Block suspicious IPs automatically.",
        "Implement honeypots to mislead attackers.",
        "Ensure critical systems are segmented from open networks."
    ],
    'password': [
        "Enforce strong password policies (e.g., length, complexity).",
        "Enable multi-factor authentication (MFA).",
        "Monitor login attempts for brute force patterns.",
        "Secure password storage with hashing and salting."
    ],
    'benign': [
        "No action needed. Normal traffic detected."
    ]
}

def get_mitigation_for_attack(attack_type):
    """
    Retrieve mitigation measures for a given attack type.
    
    Args:
        attack_type (str): The type of attack to retrieve mitigation measures for.
    
    Returns:
        list: A list of mitigation measures or default generic measures.
    """
    # Normalize the attack type
    normalized_type = str(attack_type).strip().lower()
    
    # Retrieve mitigation measures, with a fallback to generic measures
    return MITIGATION_MEASURES.get(normalized_type, [
        "General Security Recommendations:",
        "- Regularly monitor network traffic",
        "- Keep systems and software updated",
        "- Implement multi-layered security approach",
        "- Conduct periodic security assessments"
    ])