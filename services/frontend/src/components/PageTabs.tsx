type Tab = {
  id: string;
  label: string;
};

type Props = {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
};

export function PageTabs({ tabs, active, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-4 border-b border-slate-200 dark:border-slate-800">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`border-b-2 px-1 py-3 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-950 ${
            active === tab.id
              ? "border-brand-600 text-brand-700 dark:text-brand-300"
              : "border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
