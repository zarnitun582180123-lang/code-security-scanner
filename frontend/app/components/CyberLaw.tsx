'use client';

import React, { useMemo, useState } from 'react';
import {
  Scale,
  ShieldCheck,
  Lock,
  Globe,
  AlertTriangle,
  FileText,
  ChevronRight,
  CalendarDays,
  Gavel,
  Landmark,
  Search,
  ExternalLink,
  CheckCircle2,
  Info,
  Filter,
  BookOpen,
} from 'lucide-react';

interface CyberLawItem {
  id: string;
  title: string;
  lawNo: string;
  category: string;
  categoryType: 'core' | 'related';
  enacted: string;
  effective: string;
  sections: string;
  offence: string;
  penalty: string;
  status: string;
  description: string;
  sourceUrl: string;
  sourceName: string;
  icon: React.ReactNode;
}

const cyberLaws: CyberLawItem[] = [
  {
    id: 'cybersecurity-law-2025',
    title: 'Cybersecurity Law',
    lawNo: 'State Administration Council Law No. 1/2025',
    category: 'Cybersecurity',
    categoryType: 'core',
    enacted: '1 January 2025',
    effective: 'By notification',
    sections: 'Sections 1–65',
    offence:
      'Unauthorized access, disclosure, transmission, distribution, use, disruption, alteration or obstruction of information/cyber resources; offences involving critical information infrastructure, cybersecurity services and digital platform services.',
    penalty:
      'Varies by offence. Certain critical-infrastructure and cybersecurity offences may involve imprisonment, MMK fines and/or other statutory consequences. Exact penalty must be checked against the applicable section.',
    status: 'Enacted — effective date prescribed by notification',
    description:
      'Myanmar’s principal cybersecurity legislation covering cybersecurity governance, critical information infrastructure, cybersecurity service providers, digital platform services and cyber-related offences.',
    sourceUrl:
      'https://www.moi.gov.mm/moi%3Aeng/index.php/news/16633',
    sourceName: 'Myanmar Ministry of Information',
    icon: <ShieldCheck className="w-5 h-5" />,
  },

  {
    id: 'electronic-transactions-2004',
    title: 'Electronic Transactions Law',
    lawNo: 'State Peace and Development Council Law No. 5/2004',
    category: 'Electronic Transactions',
    categoryType: 'core',
    enacted: '30 April 2004',
    effective: '30 April 2004',
    sections: 'Sections 33–38',
    offence:
      'Certain prohibited acts committed using electronic transaction technology, including specified interference, misuse, alteration and other electronic-transaction related offences.',
    penalty:
      'Section 33 provides imprisonment from 7 years up to 15 years and may also impose a fine. Other offences have penalties depending on the applicable section.',
    status: 'In force — amended',
    description:
      'Establishes the legal framework for electronic records, electronic data messages, electronic signatures, electronic contracts and specified electronic offences.',
    sourceUrl:
      'https://servicetrade.gov.mm/service/law-detail/the-electronic-transactions-law',
    sourceName: 'STIP / Government legal database',
    icon: <FileText className="w-5 h-5" />,
  },

  {
    id: 'electronic-transactions-amendment-2014',
    title: 'Electronic Transactions Law Amendment',
    lawNo: 'Pyidaungsu Hluttaw Law No. 6/2014',
    category: 'Cyber Offences',
    categoryType: 'core',
    enacted: '25 February 2014',
    effective: '25 February 2014',
    sections: 'Amended Sections 33–36',
    offence:
      'Revised specified offences and penalties for conduct carried out using electronic transaction technology.',
    penalty:
      'Penalties depend on the amended offence and section. The amendment specifically revised the offence and penalty provisions in Chapter XII.',
    status: 'In force as amendment',
    description:
      'Amends the Electronic Transactions Law, particularly its cyber/electronic offence and penalty provisions.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/legal/217',
    sourceName: 'Myanmar National Trade Portal',
    icon: <Gavel className="w-5 h-5" />,
  },

  {
    id: 'electronic-transactions-amendment-2021',
    title: 'Electronic Transactions Law — 2021 Amendments',
    lawNo: 'Electronic Transactions Law amendment / related 2021 changes',
    category: 'Digital / Cyber',
    categoryType: 'core',
    enacted: '2021',
    effective: 'Verify applicable notification / amendment text',
    sections: 'Amended provisions — verify current text',
    offence:
      'Digital and electronic-transaction related conduct regulated by the amended law.',
    penalty:
      'Penalty depends on the specific offence and the current consolidated legal text.',
    status: 'Requires verification against current official consolidated text',
    description:
      'Included as a digital/cyber-related legislative update. The application should display the current official text before relying on a specific penalty.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/ecommerce',
    sourceName: 'Myanmar National Trade Portal',
    icon: <Info className="w-5 h-5" />,
  },

  {
    id: 'telecommunications-law-2013',
    title: 'Telecommunications Law',
    lawNo: 'Pyidaungsu Hluttaw Law No. 31/2013',
    category: 'Telecommunications',
    categoryType: 'core',
    enacted: '8 October 2013',
    effective: '8 October 2013',
    sections: 'Sections 75–86 / offence provisions',
    offence:
      'Unauthorized telecommunications activities, misuse of telecommunications networks or equipment, interference and other prohibited telecommunications conduct.',
    penalty:
      'Penalties vary according to the offence and applicable section. Imprisonment and/or fines may apply.',
    status: 'In force — subject to amendments and current regulations',
    description:
      'Regulates telecommunications services, networks, equipment and related offences within Myanmar’s telecommunications framework.',
    sourceUrl:
      'https://servicetrade.gov.mm/service/law-detail/the-telecommunications-law',
    sourceName: 'STIP / Government legal database',
    icon: <Globe className="w-5 h-5" />,
  },

  {
    id: 'computer-science-development-law-1996',
    title: 'Computer Science Development Law',
    lawNo: 'Computer Science Development Law',
    category: 'Computer / Cyber',
    categoryType: 'core',
    enacted: '1996',
    effective: '1996',
    sections: 'Licence / registration / offence provisions',
    offence:
      'Specified activities involving computers, computer networks, computer-related services and regulated computer resources without required authorization.',
    penalty:
      'Penalties vary according to the applicable offence and section. Verify the current official text before presenting a specific MMK amount.',
    status: 'Historical computer-related legislation — verify current applicability',
    description:
      'An earlier Myanmar computer-sector law relevant to the historical development of computer and technology regulation.',
    sourceUrl:
      'https://myanmar.gov.mm/en/documents/law-justice',
    sourceName: 'Myanmar National Portal — Law & Justice',
    icon: <BookOpen className="w-5 h-5" />,
  },

  {
    id: 'privacy-security-citizens-2017',
    title: 'Law Protecting the Privacy and Security of Citizens',
    lawNo: 'Law Protecting the Privacy and Security of Citizens',
    category: 'Privacy',
    categoryType: 'core',
    enacted: '8 March 2017',
    effective: '8 March 2017',
    sections: 'Privacy and security protections',
    offence:
      'Conduct violating protected privacy and security rights as defined by the law and applicable amendments.',
    penalty:
      'Consequences depend on the relevant provision and applicable amendments. Verify the current consolidated text before relying on a specific penalty.',
    status: 'Enacted — amendments / current application should be verified',
    description:
      'Provides statutory protections relating to privacy and security of citizens and is relevant to privacy and information-handling discussions.',
    sourceUrl:
      'https://myanmar.gov.mm/en/documents/law-justice',
    sourceName: 'Myanmar National Portal — Law & Justice',
    icon: <Lock className="w-5 h-5" />,
  },

  {
    id: 'consumer-protection-2019',
    title: 'Consumer Protection Law',
    lawNo: 'Pyidaungsu Hluttaw Law — 2019',
    category: 'E-Commerce',
    categoryType: 'related',
    enacted: '15 May 2019',
    effective: '2019',
    sections: 'Relevant consumer rights / prohibited conduct',
    offence:
      'False or misleading representations, prohibited business practices and other conduct affecting consumer rights, including digital/e-commerce contexts where applicable.',
    penalty:
      'Administrative action, fines and other consequences may apply depending on the offence and section.',
    status: 'In force',
    description:
      'Relevant to online businesses, e-commerce services, digital advertising and consumer-facing technology platforms.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/legal/2',
    sourceName: 'Myanmar National Trade Portal',
    icon: <ShieldCheck className="w-5 h-5" />,
  },

  {
    id: 'competition-law-2015',
    title: 'Competition Law',
    lawNo: 'Competition Law 2015',
    category: 'Digital Business',
    categoryType: 'related',
    enacted: '2015',
    effective: '2015',
    sections: 'Sections 13, 34–39',
    offence:
      'Prohibited anti-competitive conduct and violations of restrictions established under the Competition Law.',
    penalty:
      'Section 39 provides imprisonment up to 3 years or a fine up to MMK 15,000,000, or both, for specified violations of Section 13. Administrative fines and business closure can also apply.',
    status: 'In force',
    description:
      'Relevant to digital platforms, online marketplaces and technology businesses where competition law obligations apply.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/uploads/legals/2018/5/Competition%20Law%202015%28Eng%29.pdf',
    sourceName: 'Myanmar National Trade Portal',
    icon: <Landmark className="w-5 h-5" />,
  },

  {
    id: 'copyright-law-2019',
    title: 'Copyright Law',
    lawNo: 'Pyidaungsu Hluttaw Law No. 15/2019',
    category: 'Digital Content',
    categoryType: 'related',
    enacted: '24 May 2019',
    effective: '31 October 2023',
    sections: 'Copyright infringement provisions',
    offence:
      'Unauthorized reproduction, distribution, communication, adaptation or other infringement of protected works, subject to statutory exceptions.',
    penalty:
      'Civil and criminal remedies may apply depending on the infringement and relevant provision. Verify the specific section before displaying a fixed MMK penalty.',
    status: 'In force',
    description:
      'Protects copyright in literary, artistic and related works, including digital content where protected by the law.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/ecommerce',
    sourceName: 'Myanmar National Trade Portal',
    icon: <FileText className="w-5 h-5" />,
  },

  {
    id: 'trademark-law-2019',
    title: 'Trademark Law',
    lawNo: 'Pyidaungsu Hluttaw Law No. 3/2019',
    category: 'Digital Brand',
    categoryType: 'related',
    enacted: '30 January 2019',
    effective: '1 April 2023',
    sections: 'Trademark registration / infringement provisions',
    offence:
      'Unauthorized use or infringement of protected trademarks and other prohibited trademark-related conduct.',
    penalty:
      'Civil and criminal consequences may apply depending on the infringement and applicable section.',
    status: 'In force',
    description:
      'Provides trademark registration and protection relevant to digital brands, software products, online businesses and platform identities.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/ecommerce',
    sourceName: 'Myanmar National Trade Portal',
    icon: <Scale className="w-5 h-5" />,
  },

  {
    id: 'patent-law-2019',
    title: 'Patent Law',
    lawNo: 'Pyidaungsu Hluttaw Law — 2019',
    category: 'Technology / IP',
    categoryType: 'related',
    enacted: '2019',
    effective: '2024 — verify specific commencement',
    sections: 'Patent rights / infringement provisions',
    offence:
      'Unauthorized exploitation or infringement of protected patent rights and other prohibited patent-related conduct.',
    penalty:
      'Legal remedies and penalties depend on the specific infringement and applicable provision. Verify the current official text for an exact MMK amount.',
    status: 'In force / implementation subject to applicable rules',
    description:
      'Protects eligible inventions and is relevant to technology companies, software-adjacent inventions and digital innovation.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/ecommerce',
    sourceName: 'Myanmar National Trade Portal',
    icon: <BookOpen className="w-5 h-5" />,
  },

  {
    id: 'industrial-design-law-2019',
    title: 'Industrial Design Law',
    lawNo: 'Pyidaungsu Hluttaw Law — 2019',
    category: 'Digital / IP',
    categoryType: 'related',
    enacted: '2019',
    effective: 'Verify current commencement',
    sections: 'Industrial design registration / infringement provisions',
    offence:
      'Unauthorized use, reproduction or infringement of protected industrial designs.',
    penalty:
      'Civil and/or criminal consequences may apply depending on the relevant provision. Exact MMK penalties should be verified from the current official text.',
    status: 'In force / implementation subject to applicable rules',
    description:
      'Protects industrial designs and can be relevant to technology products, device design and digital product ecosystems.',
    sourceUrl:
      'https://www.myanmartradeportal.gov.mm/en/ecommerce',
    sourceName: 'Myanmar National Trade Portal',
    icon: <ShieldCheck className="w-5 h-5" />,
  },

  {
    id: 'myanmar-investment-law-2016',
    title: 'Myanmar Investment Law',
    lawNo: 'Pyidaungsu Hluttaw Law No. 40/2016',
    category: 'Digital Business',
    categoryType: 'related',
    enacted: '18 October 2016',
    effective: '18 October 2016',
    sections: 'Investor rights / obligations / prohibited investment activities',
    offence:
      'Non-compliance with statutory investment obligations, permits, conditions and restrictions applicable to an investor or investment.',
    penalty:
      'Administrative measures and other legal consequences depend on the relevant provision, permit and investment activity.',
    status: 'In force',
    description:
      'Provides the investment framework relevant to technology companies and digital businesses operating or investing in Myanmar.',
    sourceUrl:
      'https://myanmartradeportal.gov.mm/uploads/ecommerce/2019/10/Myanmar%20Investment%20Law%202016%20%28Eng%29.pdf',
    sourceName: 'Myanmar National Trade Portal',
    icon: <Landmark className="w-5 h-5" />,
  },
];

export default function CyberLaw() {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'core' | 'related'>('all');
  const [selectedLaw, setSelectedLaw] = useState<CyberLawItem | null>(null);

  const filteredLaws = useMemo(() => {
    const query = search.toLowerCase().trim();

    return cyberLaws.filter((law) => {
      const matchesFilter =
        filter === 'all' || law.categoryType === filter;

      const matchesSearch =
        !query ||
        law.title.toLowerCase().includes(query) ||
        law.category.toLowerCase().includes(query) ||
        law.lawNo.toLowerCase().includes(query) ||
        law.offence.toLowerCase().includes(query);

      return matchesFilter && matchesSearch;
    });
  }, [search, filter]);

  return (
    <section className="w-full max-w-7xl mx-auto">

      {/* =====================================================
          HEADER
      ====================================================== */}
      <div className="mb-8">

        <div className="flex flex-wrap items-center gap-3">

          <div className="
            inline-flex items-center gap-2
            px-3 py-1.5
            rounded-full
            bg-cyan-500/10
            border border-cyan-500/20
            text-cyan-400
            text-xs font-bold
            tracking-wider
          ">
            <Scale className="w-4 h-4" />
            CYBER LAW & COMPLIANCE
          </div>

          <div className="
            px-2.5 py-1
            rounded-full
            bg-emerald-500/10
            border border-emerald-500/20
            text-emerald-400
            text-[10px] font-bold
          ">
            MYANMAR
          </div>

        </div>

        <h2 className="
          mt-4
          text-3xl md:text-4xl
          font-black
          tracking-tight
          text-white
        ">
          Myanmar Cyber & Digital Laws
        </h2>

        <p className="
          mt-3
          text-sm
          leading-relaxed
          text-slate-400
          max-w-4xl
        ">
          A structured reference of Myanmar laws relevant to cybersecurity,
          electronic transactions, telecommunications, privacy, digital
          business, intellectual property and technology.
        </p>

        <div className="
          mt-4
          flex flex-wrap gap-3
          text-[10px]
          font-mono
          text-slate-500
        ">
          <span>14 LEGAL REFERENCES</span>
          <span>•</span>
          <span>MMK PENALTIES</span>
          <span>•</span>
          <span>OFFICIAL / GOVERNMENT SOURCES</span>
        </div>

      </div>

      {/* =====================================================
          SEARCH + FILTER
      ====================================================== */}
      <div className="
        mb-6
        p-4
        rounded-2xl
        bg-slate-900/80
        border border-slate-800
        shadow-xl
      ">

        <div className="
          flex flex-col lg:flex-row
          gap-3
        ">

          <div className="relative flex-1">

            <Search className="
              absolute
              left-4 top-1/2
              -translate-y-1/2
              w-4 h-4
              text-slate-500
            " />

            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search law, section, offence, category..."
              className="
                w-full
                bg-slate-950
                border border-slate-800
                rounded-xl
                pl-11 pr-4 py-3
                text-sm
                text-slate-200
                placeholder:text-slate-600
                outline-none
                focus:border-cyan-500/50
                transition-colors
              "
            />

          </div>

          <div className="
            flex items-center gap-2
            bg-slate-950
            border border-slate-800
            rounded-xl
            p-1.5
          ">

            <Filter className="w-4 h-4 text-slate-500 ml-2" />

            {[
              ['all', 'All Laws'],
              ['core', 'Core Cyber'],
              ['related', 'Digital / Related'],
            ].map(([value, label]) => (

              <button
                key={value}
                type="button"
                onClick={() =>
                  setFilter(value as 'all' | 'core' | 'related')
                }
                className={`
                  px-3 py-2
                  rounded-lg
                  text-[10px]
                  font-bold
                  transition-all
                  ${
                    filter === value
                      ? 'bg-cyan-500 text-slate-950'
                      : 'text-slate-500 hover:text-slate-200 hover:bg-slate-800'
                  }
                `}
              >
                {label}
              </button>

            ))}

          </div>

        </div>

      </div>

      {/* =====================================================
          STATISTICS
      ====================================================== */}
      <div className="
        grid
        grid-cols-2
        md:grid-cols-4
        gap-3
        mb-6
      ">

        <div className="
          p-4 rounded-xl
          bg-slate-900/70
          border border-slate-800
        ">
          <div className="text-[9px] uppercase tracking-widest text-slate-500">
            Total References
          </div>
          <div className="mt-1 text-2xl font-black text-white">
            {cyberLaws.length}
          </div>
        </div>

        <div className="
          p-4 rounded-xl
          bg-cyan-500/5
          border border-cyan-500/15
        ">
          <div className="text-[9px] uppercase tracking-widest text-cyan-500">
            Core Cyber
          </div>
          <div className="mt-1 text-2xl font-black text-cyan-400">
            {cyberLaws.filter((x) => x.categoryType === 'core').length}
          </div>
        </div>

        <div className="
          p-4 rounded-xl
          bg-indigo-500/5
          border border-indigo-500/15
        ">
          <div className="text-[9px] uppercase tracking-widest text-indigo-400">
            Digital Related
          </div>
          <div className="mt-1 text-2xl font-black text-indigo-300">
            {cyberLaws.filter((x) => x.categoryType === 'related').length}
          </div>
        </div>

        <div className="
          p-4 rounded-xl
          bg-emerald-500/5
          border border-emerald-500/15
        ">
          <div className="text-[9px] uppercase tracking-widest text-emerald-500">
            Currency
          </div>
          <div className="mt-1 text-lg font-black text-emerald-400">
            MMK / KYAT
          </div>
        </div>

      </div>

      {/* =====================================================
          LAW CARDS
      ====================================================== */}
      <div className="
        grid
        grid-cols-1
        xl:grid-cols-2
        gap-5
      ">

        {filteredLaws.map((law) => (

          <article
            key={law.id}
            className="
              group
              relative
              rounded-2xl
              bg-slate-900/80
              border border-slate-800
              hover:border-cyan-500/40
              hover:bg-slate-900
              transition-all duration-300
              shadow-xl
              overflow-hidden
            "
          >

            {/* Top accent */}
            <div className="
              absolute top-0 left-0 right-0
              h-px
              bg-gradient-to-r
              from-transparent
              via-cyan-500/50
              to-transparent
              opacity-0
              group-hover:opacity-100
              transition-opacity
            " />

            <div className="p-6">

              {/* TITLE */}
              <div className="
                flex
                items-start
                justify-between
                gap-4
              ">

                <div className="flex items-start gap-4">

                  <div className="
                    shrink-0
                    w-12 h-12
                    rounded-xl
                    bg-cyan-500/10
                    border border-cyan-500/20
                    flex items-center justify-center
                    text-cyan-400
                    group-hover:bg-cyan-500/20
                    transition-colors
                  ">
                    {law.icon}
                  </div>

                  <div>

                    <h3 className="
                      text-base
                      font-black
                      text-white
                    ">
                      {law.title}
                    </h3>

                    <p className="
                      mt-1
                      text-[10px]
                      font-mono
                      text-cyan-400
                    ">
                      {law.lawNo}
                    </p>

                  </div>

                </div>

                <span className="
                  shrink-0
                  text-[9px]
                  font-bold
                  tracking-wider
                  text-cyan-400
                  bg-cyan-500/10
                  border border-cyan-500/20
                  px-2 py-1
                  rounded-full
                ">
                  {law.category}
                </span>

              </div>

              {/* DATES */}
              <div className="
                mt-5
                grid grid-cols-2
                gap-3
              ">

                <div className="
                  p-3
                  rounded-lg
                  bg-slate-950/70
                  border border-slate-800
                ">

                  <div className="
                    flex items-center gap-1.5
                    text-[9px]
                    text-slate-500
                    uppercase
                    tracking-wider
                  ">
                    <CalendarDays className="w-3 h-3" />
                    Enacted
                  </div>

                  <div className="
                    mt-1
                    text-xs
                    font-bold
                    text-slate-200
                  ">
                    {law.enacted}
                  </div>

                </div>

                <div className="
                  p-3
                  rounded-lg
                  bg-slate-950/70
                  border border-slate-800
                ">

                  <div className="
                    flex items-center gap-1.5
                    text-[9px]
                    text-slate-500
                    uppercase
                    tracking-wider
                  ">
                    <CheckCircle2 className="w-3 h-3" />
                    Effective
                  </div>

                  <div className="
                    mt-1
                    text-xs
                    font-bold
                    text-slate-200
                  ">
                    {law.effective}
                  </div>

                </div>

              </div>

              {/* SECTION */}
              <div className="
                mt-3
                p-3
                rounded-lg
                bg-slate-950/70
                border border-slate-800
              ">

                <div className="
                  flex items-center gap-1.5
                  text-[9px]
                  text-slate-500
                  uppercase
                  tracking-wider
                ">
                  <Landmark className="w-3 h-3" />
                  Relevant Sections
                </div>

                <div className="
                  mt-1
                  text-xs
                  font-bold
                  font-mono
                  text-cyan-300
                ">
                  {law.sections}
                </div>

              </div>

              {/* SCOPE */}
              <div className="mt-5">

                <div className="
                  text-[10px]
                  font-bold
                  text-cyan-400
                  uppercase
                  tracking-widest
                  mb-2
                ">
                  Scope
                </div>

                <p className="
                  text-xs
                  leading-relaxed
                  text-slate-400
                ">
                  {law.description}
                </p>

              </div>

              {/* OFFENCE */}
              <div className="
                mt-4
                p-4
                rounded-xl
                bg-amber-500/5
                border border-amber-500/15
              ">

                <div className="
                  flex items-center gap-2
                  text-[10px]
                  font-bold
                  text-amber-400
                  uppercase
                  tracking-widest
                ">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Offence / Prohibited Conduct
                </div>

                <p className="
                  mt-2
                  text-xs
                  leading-relaxed
                  text-slate-300
                ">
                  {law.offence}
                </p>

              </div>

              {/* PENALTY */}
              <div className="
                mt-4
                p-4
                rounded-xl
                bg-rose-500/5
                border border-rose-500/15
              ">

                <div className="
                  flex items-center gap-2
                  text-[10px]
                  font-bold
                  text-rose-400
                  uppercase
                  tracking-widest
                ">
                  <Gavel className="w-3.5 h-3.5" />
                  Potential Penalty — MMK
                </div>

                <p className="
                  mt-2
                  text-xs
                  leading-relaxed
                  text-slate-300
                ">
                  {law.penalty}
                </p>

              </div>

              {/* STATUS */}
              <div className="
                mt-4
                flex
                items-center
                justify-between
                gap-3
                p-3
                rounded-lg
                bg-slate-950
                border border-slate-800
              ">

                <div>

                  <div className="
                    text-[9px]
                    uppercase
                    tracking-widest
                    text-slate-600
                  ">
                    Legal Status
                  </div>

                  <div className="
                    mt-1
                    text-xs
                    font-semibold
                    text-slate-300
                  ">
                    {law.status}
                  </div>

                </div>

                <div className="
                  shrink-0
                  w-2 h-2
                  rounded-full
                  bg-emerald-400
                  shadow-[0_0_10px_rgba(52,211,153,0.7)]
                " />

              </div>

              {/* FOOTER */}
              <div className="
                mt-4
                flex
                items-center
                justify-between
              ">

                <button
                  type="button"
                  onClick={() => setSelectedLaw(law)}
                  className="
                    flex
                    items-center
                    gap-1
                    text-[10px]
                    font-bold
                    text-slate-500
                    hover:text-cyan-400
                    transition-colors
                  "
                >
                  <span>VIEW DETAILS</span>
                  <ChevronRight className="w-3 h-3" />
                </button>

                <a
                  href={law.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="
                    flex
                    items-center
                    gap-1.5
                    text-[10px]
                    font-bold
                    text-cyan-500
                    hover:text-cyan-300
                    transition-colors
                  "
                >
                  <ExternalLink className="w-3 h-3" />
                  OFFICIAL SOURCE
                </a>

              </div>

            </div>

          </article>

        ))}

      </div>

      {/* EMPTY */}
      {filteredLaws.length === 0 && (

        <div className="
          p-10
          text-center
          rounded-2xl
          bg-slate-900/60
          border border-slate-800
        ">

          <Search className="
            w-8 h-8
            text-slate-600
            mx-auto
          " />

          <p className="
            mt-3
            text-sm
            text-slate-400
          ">
            No matching legal reference found.
          </p>

        </div>

      )}

      {/* =====================================================
          DETAILS MODAL
      ====================================================== */}
      {selectedLaw && (

        <div
          className="
            fixed
            inset-0
            z-[100]
            bg-black/70
            backdrop-blur-sm
            flex
            items-center
            justify-center
            p-4
          "
          onClick={() => setSelectedLaw(null)}
        >

          <div
            className="
              w-full
              max-w-3xl
              max-h-[90vh]
              overflow-y-auto
              bg-[#080d18]
              border border-cyan-500/20
              rounded-2xl
              shadow-[0_0_60px_rgba(6,182,212,0.15)]
            "
            onClick={(e) => e.stopPropagation()}
          >

            <div className="
              sticky top-0
              p-5
              bg-[#080d18]/95
              backdrop-blur-xl
              border-b border-slate-800
              flex
              items-center
              justify-between
              gap-4
            ">

              <div className="flex items-center gap-3">

                <div className="
                  w-10 h-10
                  rounded-lg
                  bg-cyan-500/10
                  border border-cyan-500/20
                  flex items-center justify-center
                  text-cyan-400
                ">
                  {selectedLaw.icon}
                </div>

                <div>

                  <h3 className="
                    text-sm
                    font-black
                    text-white
                  ">
                    {selectedLaw.title}
                  </h3>

                  <p className="
                    text-[10px]
                    font-mono
                    text-cyan-400
                  ">
                    {selectedLaw.lawNo}
                  </p>

                </div>

              </div>

              <button
                type="button"
                onClick={() => setSelectedLaw(null)}
                className="
                  w-8 h-8
                  rounded-lg
                  bg-slate-900
                  border border-slate-800
                  text-slate-500
                  hover:text-white
                  transition-colors
                "
              >
                ×
              </button>

            </div>

            <div className="p-6 space-y-5">

              <div className="
                grid
                grid-cols-1
                sm:grid-cols-2
                gap-3
              ">

                <InfoBox
                  label="Enacted"
                  value={selectedLaw.enacted}
                />

                <InfoBox
                  label="Effective"
                  value={selectedLaw.effective}
                />

                <InfoBox
                  label="Sections"
                  value={selectedLaw.sections}
                />

                <InfoBox
                  label="Legal Status"
                  value={selectedLaw.status}
                />

              </div>

              <DetailBlock
                title="Description"
                text={selectedLaw.description}
              />

              <DetailBlock
                title="Offence / Prohibited Conduct"
                text={selectedLaw.offence}
              />

              <DetailBlock
                title="Potential Penalty — MMK"
                text={selectedLaw.penalty}
                danger
              />

              <a
                href={selectedLaw.sourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="
                  flex
                  items-center
                  justify-center
                  gap-2
                  w-full
                  px-4 py-3
                  rounded-xl
                  bg-cyan-500/10
                  border border-cyan-500/20
                  text-cyan-400
                  text-xs
                  font-bold
                  hover:bg-cyan-500/20
                  transition-colors
                "
              >
                <ExternalLink className="w-4 h-4" />
                OPEN {selectedLaw.sourceName}
              </a>

            </div>

          </div>

        </div>

      )}

      {/* =====================================================
          LEGAL NOTICE
      ====================================================== */}
      <div className="
        mt-6
        p-5
        rounded-2xl
        bg-amber-500/5
        border border-amber-500/20
      ">

        <div className="flex gap-3">

          <AlertTriangle className="
            w-5 h-5
            text-amber-400
            shrink-0
            mt-0.5
          " />

          <div>

            <h4 className="
              text-xs
              font-bold
              text-amber-400
              uppercase
              tracking-wider
            ">
              Legal Data Notice
            </h4>

            <p className="
              mt-1.5
              text-[11px]
              leading-relaxed
              text-slate-400
            ">
              This module is a cybersecurity education and compliance
              reference, not legal advice. Laws may be amended, repealed,
              replaced or supplemented by notifications, rules and
              regulations. Penalties shown here should be verified against
              the latest official consolidated law before being relied upon
              for legal, compliance or operational decisions.
            </p>

          </div>

        </div>

      </div>

    </section>
  );
}

/* =========================================================
   SMALL COMPONENTS
========================================================= */

function InfoBox({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="
      p-4
      rounded-xl
      bg-slate-950
      border border-slate-800
    ">

      <div className="
        text-[9px]
        uppercase
        tracking-widest
        text-slate-600
      ">
        {label}
      </div>

      <div className="
        mt-1.5
        text-xs
        font-bold
        leading-relaxed
        text-slate-200
      ">
        {value}
      </div>

    </div>
  );
}

function DetailBlock({
  title,
  text,
  danger = false,
}: {
  title: string;
  text: string;
  danger?: boolean;
}) {
  return (
    <div
      className={`
        p-4
        rounded-xl
        border
        ${
          danger
            ? 'bg-rose-500/5 border-rose-500/15'
            : 'bg-slate-950 border-slate-800'
        }
      `}
    >

      <div
        className={`
          text-[10px]
          font-bold
          uppercase
          tracking-widest
          ${
            danger
              ? 'text-rose-400'
              : 'text-cyan-400'
          }
        `}
      >
        {title}
      </div>

      <p className="
        mt-2
        text-xs
        leading-relaxed
        text-slate-300
      ">
        {text}
      </p>

    </div>
  );
}