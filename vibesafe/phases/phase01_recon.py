"""
Phase 1: Information Gathering / Reconnaissance
"""

import time
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, TechStack
from vibesafe.utils import read_json_file, read_file_safe, find_files_by_name, find_files_by_pattern
from vibesafe.ui import print_tech_stack

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # Initialize TechStack
    stack = TechStack()

    # Walk directory to find package.json or other manifest files
    package_json_files = find_files_by_name(config, ["package.json"])
    requirements_txt_files = find_files_by_name(config, ["requirements.txt"])
    pyproject_toml_files = find_files_by_name(config, ["pyproject.toml"])
    
    # ─── Framework & Dependency Analysis ──────────────────────────────────
    deps = {}
    if package_json_files:
        stack.package_manager = "npm/yarn/pnpm"
        pkg_data = read_json_file(package_json_files[0])
        if pkg_data:
            dependencies = pkg_data.get("dependencies", {})
            dev_dependencies = pkg_data.get("devDependencies", {})
            deps = {**dependencies, **dev_dependencies}
            stack.total_dependencies = len(deps)

            # Framework detection
            if "next" in deps:
                stack.framework = f"Next.js ({deps.get('next', 'unknown')})"
                stack.runtime = "Node.js"
            elif "react" in deps:
                stack.framework = f"React ({deps.get('react', 'unknown')})"
                stack.runtime = "Browser / Node"
            elif "express" in deps:
                stack.framework = f"Express ({deps.get('express', 'unknown')})"
                stack.runtime = "Node.js"
            elif "vue" in deps:
                stack.framework = f"Vue.js ({deps.get('vue', 'unknown')})"
                stack.runtime = "Browser"
            elif "svelte" in deps:
                stack.framework = f"Svelte ({deps.get('svelte', 'unknown')})"
                stack.runtime = "Browser"
            elif "@astrojs/compiler" in deps or "astro" in deps:
                stack.framework = "Astro"
                stack.runtime = "Node.js"

            # Database/ORM detection
            if "prisma" in deps or "@prisma/client" in deps:
                stack.orm = "Prisma ORM"
            if "mongoose" in deps:
                stack.database = "MongoDB (Mongoose)"
            if "@supabase/supabase-js" in deps:
                stack.database = "Supabase (PostgreSQL)"
                stack.auth = "Supabase Auth"
            if "pg" in deps or "postgres" in deps:
                stack.database = "PostgreSQL"
            if "mysql" in deps or "mysql2" in deps:
                stack.database = "MySQL"
            if "mongodb" in deps:
                stack.database = "MongoDB"
            if "sequelize" in deps:
                stack.orm = "Sequelize"

            # Auth detection
            if "next-auth" in deps or "@auth/core" in deps:
                stack.auth = "NextAuth.js"
            elif "@clerk/nextjs" in deps or "@clerk/clerk-react" in deps:
                stack.auth = "Clerk Auth"
            elif "passport" in deps:
                stack.auth = "Passport.js"
            elif "firebase-admin" in deps or "firebase" in deps:
                stack.auth = "Firebase Auth"

            # Payments detection
            if "stripe" in deps or "@stripe/stripe-js" in deps:
                stack.payments = "Stripe"
            if "razorpay" in deps:
                stack.payments = "Razorpay"

            # Storage detection
            if "cloudinary" in deps:
                stack.storage = "Cloudinary"
            if "@aws-sdk/client-s3" in deps or "aws-sdk" in deps:
                stack.storage = "AWS S3"

            # CSS/Styling
            if "tailwindcss" in deps:
                stack.css_framework = "Tailwind CSS"
            elif "styled-components" in deps:
                stack.css_framework = "Styled Components"

            # Email services
            if "resend" in deps:
                stack.email = "Resend"
            elif "nodemailer" in deps:
                stack.email = "Nodemailer"
            elif "@sendgrid/mail" in deps:
                stack.email = "SendGrid"

    # Python framework detection
    if requirements_txt_files or pyproject_toml_files:
        stack.package_manager = "pip/poetry"
        stack.runtime = "Python"
        content = ""
        if requirements_txt_files:
            content = read_file_safe(requirements_txt_files[0]) or ""
        elif pyproject_toml_files:
            content = read_file_safe(pyproject_toml_files[0]) or ""

        if "django" in content.lower():
            stack.framework = "Django"
            stack.database = "SQLite/PostgreSQL"
            stack.orm = "Django ORM"
        elif "flask" in content.lower():
            stack.framework = "Flask"
        elif "fastapi" in content.lower():
            stack.framework = "FastAPI"

    # Fallback to language and folder structure detection
    if not stack.runtime:
        if find_files_by_pattern(config, "*.py"):
            stack.runtime = "Python"
        elif find_files_by_pattern(config, "*.js") or find_files_by_pattern(config, "*.ts"):
            stack.runtime = "Node.js"
        else:
            stack.runtime = "Static HTML / JS"

    # Detect Hosting clues
    if find_files_by_name(config, ["vercel.json"]):
        stack.hosting = "Vercel"
    elif find_files_by_name(config, ["netlify.toml"]):
        stack.hosting = "Netlify"
    elif find_files_by_name(config, ["fly.toml"]):
        stack.hosting = "Fly.io"
    elif find_files_by_name(config, ["Dockerfile"]):
        stack.hosting = "Dockerized Host (e.g. AWS, Render, GCP)"

    # Count API Routes
    api_files_nextjs = find_files_by_pattern(config, "*/api/*.*")
    api_files_express = find_files_by_pattern(config, "*/routes/*.*")
    stack.api_routes_count = len(api_files_nextjs) + len(api_files_express)

    # Let's clean up stack with defaults if missing
    if not stack.framework:
        stack.framework = "Custom / Raw HTML/JS"
    
    # Save the tech stack to the result
    result = PhaseResult(
        phase_number=1,
        phase_name="Information Gathering",
        phase_type=PhaseType.AUTOMATED,
        summary=f"Detected {stack.framework} running on {stack.runtime}.",
        duration_seconds=time.time() - start_time
    )
    result._tech_stack = stack  # Store internal ref for the engine to copy
    
    # Render table in terminal
    print_tech_stack(stack.to_dict())
    
    return result
